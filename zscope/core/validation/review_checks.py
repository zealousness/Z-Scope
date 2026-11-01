"""Narrow compiler-backed refutations. Unsupported constructs stay unknown.

No LLM assertion, regular-expression guard summary, or query count can mint a
checked proof. The signed receipt is process-local: replay must re-run checks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from ...retrieval.validation_facts import CompleteFactStore, digest, walk_ast

CHECKER_VERSION = "zscope.review-checkers.v6"
RULE_CONTRACT_REVISIONS = {
    "unsynchronized_shared_flag_or_counter": {9, 10},
    "clang_cfg_unsynchronized_shared_flag_or_counter": {9, 10},
    "clang_cfg_parent_release_without_owned_member_cleanup": {1, 7, 8, 9},
    "clang_cfg_acquire_without_release_on_exit": {1, 10, 11},
    "clang_cfg_unchecked_insert_after_ownership_handoff": {1, 8, 9},
    "clang_cfg_unbounded_count_indexes_fixed_array": {1, 6, 7, 8},
    "clang_cfg_nonliteral_format_string": {1, 6, 7, 8},
    "clang_cfg_narrowed_allocation_original_length_copy": {1, 6, 7, 8},
    "clang_cfg_return_with_lock_held": {1, 8, 9, 10},
    "clang_cfg_fd_open_return_without_close": {1, 8, 9, 10, 11},
    "clang_cfg_allocation_result_used_without_null_check": {1, 6, 7},
}
_RECEIPT_KEY = secrets.token_bytes(32)
_TRANSPARENT = {"ImplicitCastExpr", "ParenExpr", "ExprWithCleanups", "ConstantExpr"}


class _ReviewReceipt(dict[str, Any]):
    """Live contract dependency, following the protocol-assessment receipt model."""

    def __init__(self, payload: dict[str, Any], registry: Any):
        super().__init__(payload)
        version = payload["contract_version"]
        self.registry_current = lambda: registry.version == version


def strip(node: Dict[str, Any]) -> Dict[str, Any]:
    while node.get("kind") in _TRANSPARENT and len(node.get("inner", [])) == 1:
        if node.get("kind") == "ImplicitCastExpr" and node.get("castKind") not in {
            "LValueToRValue",
            "ArrayToPointerDecay",
            "FunctionToPointerDecay",
            "NoOp",
        }:
            child = node["inner"][0]
            if not (
                node.get("castKind") == "BitCast"
                and str(node.get("type", {}).get("qualType", "")).endswith("*")
                and str(child.get("type", {}).get("qualType", "")).endswith("*")
            ):
                break
        node = node["inner"][0]
    return node


def symbol(node: Dict[str, Any]) -> str:
    node = strip(node)
    if node.get("kind") == "DeclRefExpr":
        return str(node.get("referencedDecl", {}).get("id") or "")
    if node.get("kind") == "MemberExpr":
        children = node.get("inner", [])
        return symbol(children[0]) + "." + str(node.get("name")) if children else ""
    if node.get("kind") == "UnaryOperator" and node.get("opcode") in {"&", "*"}:
        return str(node["opcode"]) + symbol(node.get("inner", [{}])[0])
    return ""


def call(node: Dict[str, Any]) -> tuple[str, list[Dict[str, Any]]]:
    node = strip(node)
    children = node.get("inner", [])
    if node.get("kind") != "CallExpr" or not children:
        return "", []
    callee = strip(children[0]).get("referencedDecl", {})
    return (
        str(callee.get("name") or "") if callee.get("kind") == "FunctionDecl" else ""
    ), children[1:]


def line_of(node: Dict[str, Any], source: str) -> int:
    loc = node.get("loc") or node.get("range", {}).get("begin", {})
    loc = loc.get("expansionLoc", loc)
    if loc.get("line"):
        return int(loc["line"])
    offset = loc.get("offset")
    return source[: int(offset)].count("\n") + 1 if offset is not None else 0


def function_in_source(node: Dict[str, Any], source: str) -> bool:
    loc = node.get("loc") or {}
    loc = loc.get("expansionLoc", loc)
    if loc.get("includedFrom"):
        return False
    return not loc.get("file") or Path(loc["file"]).resolve() == Path(source).resolve()


def integer(node: Dict[str, Any]) -> Optional[int]:
    node = strip(node)
    if node.get("kind") == "ImplicitCastExpr" and node.get("castKind") == "IntegralCast":
        value = integer(node.get("inner", [{}])[0])
        ty = node.get("type", {}).get("desugaredQualType") or node.get("type", {}).get(
            "qualType", ""
        )
        if ty in {
            "int",
            "unsigned int",
            "long",
            "unsigned long",
            "long long",
            "unsigned long long",
        }:
            if value is not None and 0 <= value <= 32767:
                return value
        return None
    if node.get("kind") in {"IntegerLiteral", "CharacterLiteral"}:
        return int(node["value"])
    if node.get("kind") == "UnaryOperator" and node.get("opcode") == "-":
        if "unsigned" in str(
            node.get("type", {}).get("desugaredQualType")
            or node.get("type", {}).get("qualType")
            or ""
        ):
            return None
        value = integer(node.get("inner", [{}])[0])
        return -value if value is not None else None
    return None


def _acquisition_selectors(issue: Dict[str, Any]) -> list[Dict[str, Any]]:
    # Candidate event text selects a subject, never supplies a cleanup fact.
    return [
        {k: e.get(k) for k in ("variable", "api", "line")}
        for e in ((issue.get("evidence_pack") or {}).get("ast_cfg") or {}).get("events", [])
        if isinstance(e, dict) and e.get("kind") == "acquire"
    ]


def _binding(issue: Dict[str, Any]) -> str:
    return digest(
        [
            {
                k: issue.get(k)
                for k in (
                    "candidate_uid",
                    "validation_cluster_uid",
                    "rule_id",
                    "category",
                    "function",
                    "file",
                    "file_path",
                    "line",
                    "location",
                    "description",
                    "source",
                    "sink",
                    "analysis_scope",
                    "trigger_condition",
                    "validator_contract",
                    "rule",
                    "rule_revision",
                    "defect_class",
                    "subcategory",
                    "obligation_uid",
                    "obligation_shape",
                    "security_obligation",
                    "validation_requirements",
                    "path_constraints",
                    "call_paths",
                    "entry_paths",
                    "contract_version",
                    "lifecycle_obligation",
                    "build_context_id",
                )
            },
            _acquisition_selectors(issue),
        ]
    )


def checked_receipt(issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate driver-issued authority, including current dependency bytes."""
    receipt = issue.get("review_checked_proof")
    if not isinstance(receipt, _ReviewReceipt):
        return None
    if not receipt.registry_current():
        return None
    if receipt.get("checker_version") != CHECKER_VERSION:
        return None
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    expected = hmac.new(_RECEIPT_KEY, digest(payload).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(receipt.get("signature") or "")):
        return None
    if receipt.get("candidate_binding") != _binding(issue):
        return None
    if receipt.get("compiler_environment") != CompleteFactStore.compiler_environment():
        return None
    if receipt.get("native_build_context"):
        from ...retrieval.build_context import context_input_status

        context = receipt["native_build_context"]
        if (
            context.get("build_context_id") != issue.get("build_context_id")
            or context_input_status(context) != "current"
        ):
            return None
    try:
        deps = receipt["dependencies"]
        if not deps or CompleteFactStore._hash_files(deps) != deps:
            return None
    except (KeyError, OSError):
        return None
    from ...retrieval.validation_facts import preprocessor_current

    if not preprocessor_current(receipt.get("preprocessor_probe")):
        return None
    return receipt


class ReviewClaimChecker:

    def __init__(
        self, store: CompleteFactStore, registry: Any = None, program_facts_provider: Any = None
    ):
        self.store = store
        self.program_facts_provider = program_facts_provider
        if registry is None:
            from ...semantics.defaults import default_local_pattern_semantics

            registry = default_local_pattern_semantics().contracts
        self.registry = registry

    def prepare(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        file = str(issue.get("file") or issue.get("file_path") or "")
        if not file:
            file = re.sub(r":\d+(?::\d+)?$", "", str(issue.get("location") or ""))
        descriptor = self.store.collect(file)
        issue["review_fact_store"] = descriptor
        if descriptor.get("complete"):
            data = self.store.load(descriptor["fact_store_id"])
            if not data.get("complete"):
                descriptor = {
                    **descriptor,
                    "complete": False,
                    "reason": data.get("reason", "compiler_facts_changed_during_prepare"),
                }
                issue["review_fact_store"] = descriptor
                return descriptor
            source = Path(data["source"]).read_text(encoding="utf-8")
            funcs = self._functions(data)
            fn = funcs.get(str(issue.get("function") or ""))
            if fn:
                start = line_of(fn, source)
                end_node = {"loc": fn.get("range", {}).get("end", {})}
                end = line_of(end_node, source)
                text = "\n".join(source.splitlines()[max(0, start - 1) : end])
                names = set(re.findall(r"\b[A-Za-z_]\w*\b", text))
                while True:
                    references = {
                        token
                        for macro in data["macros"]
                        if macro["name"] in names
                        for token in re.findall(r"\b[A-Za-z_]\w*\b", macro["body"])
                    }
                    if references <= names:
                        break
                    names |= references
                issue["review_macro_branches"] = [m for m in data["macros"] if m["name"] in names]
                issue["review_conditional_risks"] = [
                    {
                        **m,
                        "status": "needs_review",
                        "reason": "inactive_empty_macro_branch",
                        "analysis_scope": "conditional_source_branch",
                    }
                    for m in issue["review_macro_branches"]
                    if not m["active"] and m["empty_operation"] and m["condition"] != "1"
                ]
                if str(issue.get("category") or "") in {
                    "race",
                    "unsynchronized_shared_state",
                    "bounds",
                    "buffer_overflow",
                } and not issue.get("related_generation"):
                    for risk in issue["review_conditional_risks"]:
                        proposal = {
                            k: issue.get(k, "")
                            for k in (
                                "function",
                                "category",
                                "source",
                                "sink",
                                "file",
                                "location",
                                "line",
                            )
                        }
                        proposal.update(
                            description=f"条件分支下 {risk['name']} 为空操作，需对应构建验证原安全义务。",
                            trigger_condition=risk["condition"],
                            analysis_scope="conditional_source_branch",
                            evidence_refs=[descriptor["fact_store_id"]],
                        )
                        proposals = issue.setdefault("review_related_proposals", [])
                        if proposal not in proposals:
                            proposals.append(proposal)
        return descriptor

    @staticmethod
    def _functions(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        from .function_index import function_definitions

        return function_definitions(data)

    def check(self, issue: Dict[str, Any], kind: str = "auto") -> Dict[str, Any]:
        issue.pop("review_checked_proof", None)
        registry_version = self.registry.version
        descriptor = issue.get("review_fact_store") or self.prepare(issue)
        data = (
            self.store.load(str(descriptor.get("fact_store_id") or ""))
            if descriptor.get("complete")
            else descriptor
        )
        result: Dict[str, Any] = {
            "schema_version": CHECKER_VERSION,
            "status": "unknown",
            "claim_kind": kind,
            "coverage": {
                "scope": "candidate_obligation",
                "complete": False,
                "project_call_graph_complete": False,
            },
            "reason": "incomplete_compiler_facts",
            "evidence_refs": [],
        }
        if not data.get("complete") or not self.store.is_trusted(
            str(data.get("fact_store_id") or "")
        ):
            result["reason"] = data.get("reason", result["reason"])
            issue.setdefault("review_claim_checks", []).append(deepcopy(result))
            return result
        functions = self._functions(data)
        name = str(issue.get("function") or "")
        fn = functions.get(name)
        if not fn:
            result["reason"] = "function_identity_missing_or_ambiguous"
            issue.setdefault("review_claim_checks", []).append(deepcopy(result))
            return result
        if not function_in_source(fn, data["source"]):
            result["reason"] = "candidate_function_belongs_to_other_source"
            issue.setdefault("review_claim_checks", []).append(deepcopy(result))
            return result
        cfgs = [
            g for g in data["cfg"] if re.search(r"\b" + re.escape(name) + r"\s*\(", g["signature"])
        ]
        source = Path(data["source"]).read_text(encoding="utf-8")
        functions_checked: set[str] = {name}
        rule = str(issue.get("rule_id") or issue.get("rule") or "")
        category = str(issue.get("category") or issue.get("defect_class") or "")
        if issue.get("contract_version") and issue["contract_version"] != self.registry.version:
            result["reason"] = "candidate_contract_version_mismatch"
            issue.setdefault("review_claim_checks", []).append(deepcopy(result))
            return result
        if (
            rule in RULE_CONTRACT_REVISIONS
            and issue.get("rule_revision") not in RULE_CONTRACT_REVISIONS[rule]
        ):
            result["reason"] = "unqualified_rule_contract_revision"
            issue.setdefault("review_claim_checks", []).append(deepcopy(result))
            return result
        reason = "unsupported_candidate_obligation"
        proved = False
        if kind in {"auto", "format_operand"} and category == "format_string":
            # A literal at the exact original call refutes the operand claim.
            # A nonliteral value remains unknown until its data flow is checked.
            position = re.search(r":(\d+)$", str(issue.get("location") or ""))
            target_line = int(issue.get("line") or (position[1] if position else 0))
            calls = [
                n
                for n in walk_ast(fn)
                if n.get("kind") == "CallExpr" and line_of(n, source) == target_line
            ]
            operands = []
            ambiguous_operand = False
            for operation in calls:
                name_, args_ = call(operation)
                mappings = [
                    c
                    for c in self.registry.find(name_, "format_sink", str(data["source"]))
                    if not (name_ in functions and c.source.startswith("builtin"))
                ]
                if any(not mapping.effects_trusted for mapping in mappings):
                    ambiguous_operand = True
                for mapping in mappings:
                    slot = mapping.carrier.argument_index
                    if (
                        mapping.effects_trusted
                        and mapping.carrier.kind == "argument"
                        and slot is not None
                        and slot < len(args_)
                    ):
                        operands.append(strip(args_[slot]))
            proved = (
                bool(operands)
                and not ambiguous_operand
                and all(n.get("kind") == "StringLiteral" for n in operands)
            )
            reason = (
                "actual_format_operands_are_literals"
                if proved
                else "format_operand_or_input_flow_unclosed"
            )
        if (
            kind in {"auto", "type_identity"}
            and rule == "clang_cfg_parent_release_without_owned_member_cleanup"
        ):
            reason = "owned_member_identity_not_resolved"
            member = re.search(
                r"common owned member [`']?(\w+)->(\w+)", str(issue.get("description") or "")
            )
            if member is None:
                member = re.search(r"成员\s*[`']?(\w+)->(\w+)", str(issue.get("description") or ""))
            if member:
                variables = [
                    n
                    for n in walk_ast(fn)
                    if n.get("kind") in {"VarDecl", "ParmVarDecl"} and n.get("name") == member[1]
                ]
                if len(variables) == 1:
                    ty = variables[0].get("type", {})
                    typename = ty.get("desugaredQualType") or ty.get("qualType", "")
                    typename = re.sub(r"\b(?:struct|const|volatile)\b|\*", "", typename).strip()
                    records = [
                        n
                        for n in walk_ast(data["ast"])
                        if n.get("kind") == "RecordDecl"
                        and n.get("completeDefinition")
                        and n.get("name") == typename
                    ]
                    if len(records) == 1 and not any(
                        n.get("isImplicit") for n in records[0].get("inner", [])
                    ):
                        fields = {
                            n.get("name")
                            for n in records[0].get("inner", [])
                            if n.get("kind") == "FieldDecl"
                        }
                        proved = bool(fields and member[2] not in fields)
                        reason = (
                            "reported_owned_field_absent_in_complete_type"
                            if proved
                            else "owned_member_exists_without_counterproof"
                        )
                        actual = [
                            n
                            for n in records[0].get("inner", [])
                            if n.get("kind") == "FieldDecl" and n.get("name") == member[2]
                        ]
                        if len(actual) == 1 and re.fullmatch(
                            r"(?:unsigned |signed )?char\s*\[\d+\]",
                            actual[0].get("type", {}).get("qualType", ""),
                        ):
                            proved, reason = True, "reported_owned_member_is_inline_byte_storage"
        type_only = proved
        if not type_only and (len(cfgs) != 1 or not cfgs[0]["complete"]):
            result["reason"] = "function_cfg_incomplete_or_ambiguous"
            issue.setdefault("review_claim_checks", []).append(deepcopy(result))
            return result
        if (
            not proved
            and kind in {"auto", "path_separation"}
            and rule == "clang_cfg_return_with_lock_held"
        ):
            from ...retrieval.claim_paths import operation_reaches_observation

            position = re.search(r":(\d+)$", str(issue.get("location") or ""))
            target_line = int(issue.get("line") or (position[1] if position else 0))
            acquisition = re.search(r"\bat line (\d+)\b", str(issue.get("source") or ""))
            operations = set()
            if acquisition:
                for node in walk_ast(fn):
                    called, arguments = call(node)
                    if (
                        called
                        and line_of(node, source) == int(acquisition[1])
                        and any(c.effects_trusted for c in self.registry.find(called, "lock"))
                    ):
                        operations.add(str(node["id"]))
            targets = {
                str(n["id"])
                for n in walk_ast(fn)
                if n.get("kind") == "ReturnStmt" and line_of(n, source) == target_line
            }
            if operations and targets:
                complete, reaches = operation_reaches_observation(fn, operations, targets)
                proved = complete and reaches == {False}
                reason = (
                    "reported_acquisition_cannot_reach_reported_return"
                    if proved
                    else "lock_path_or_runtime_state_unclosed"
                )
        if (
            not proved
            and kind in {"auto", "copy_capacity"}
            and rule == "clang_cfg_narrowed_allocation_original_length_copy"
        ):
            proved = self._same_copy_extent(fn, issue, source, functions)
            reason = (
                "allocation_and_copy_use_same_unchanged_extent"
                if proved
                else "allocation_conversion_or_copy_extent_unclosed"
            )
        if (
            not proved
            and kind in {"auto", "ownership_cleanup"}
            and rule == "clang_cfg_fd_open_return_without_close"
        ):
            proved, reason = self._reported_descriptor_exit(fn, issue, source, functions)
        if (
            not proved
            and kind in {"auto", "ownership_cleanup", "allocation_guard"}
            and rule
            in {
                "configured_acquire_without_release",
                "clang_cfg_acquire_without_release_on_exit",
                "clang_cfg_allocation_result_used_without_null_check",
                "clang_cfg_fd_open_return_without_close",
                "clang_cfg_unchecked_insert_after_ownership_handoff",
            }
        ):
            from ...retrieval.lifecycle_analysis import lifecycle_facts

            if any(n.get("kind") == "CXXConstructExpr" for n in walk_ast(fn)):
                native = {}
                if self.program_facts_provider and issue.get("build_context_id"):
                    native = self.program_facts_provider(
                        name, data["source"], build_context_id=issue["build_context_id"]
                    )
                data = {
                    **data,
                    "raii_native_facts": native,
                    "build_context_id": issue.get("build_context_id", ""),
                }
            analysis = lifecycle_facts(self.store, self.registry, data, fn, source)
            issue["lifecycle_analysis"] = analysis
            if analysis["raii"]["manager_count"]:
                result["coverage"]["raii"] = {
                    **analysis["raii"],
                    "events": analysis["events"],
                    "gaps": analysis["gaps"],
                }
            reported = issue.get("lifecycle_obligation") or {}
            selected = [
                o
                for o in analysis["obligations"]
                if o["acquisition_id"] == reported.get("acquisition_id")
            ]
            selectors = _acquisition_selectors(issue)
            if not selected and selectors:
                groups = [
                    [
                        o
                        for o in analysis["obligations"]
                        if o["object"] == s["variable"]
                        and o["api"] == s["api"]
                        and o["line"] == s["line"]
                    ]
                    for s in selectors
                ]
                selected = [o for group in groups for o in group] if all(groups) else []
            if not selected and not selectors:
                # Legacy claims name an acquisition API rather than an object.
                # Check every matching acquisition, never MIN(call_line).
                api = str(
                    (
                        issue.get("resource_pair")
                        or (issue.get("evidence_pack") or {}).get("resource_pair")
                        or {}
                    ).get("acquire")
                    or issue.get("source")
                    or ""
                )
                selected = [o for o in analysis["obligations"] if o["api"] == api]
            if not selected and not selectors and rule != "configured_acquire_without_release":
                # Text supplies only a subject selector. The object and all
                # its acquisition sites are independently resolved from AST.
                var = re.search(
                    r"\b([A-Za-z_]\w*)\s*(?:allocated\b|=)", str(issue.get("source") or "")
                )
                if not var:
                    var = re.search(
                        r"^`(\w+)` is acquired from `\w+`", str(issue.get("description") or "")
                    )
                if var:
                    selected = [o for o in analysis["obligations"] if o["object"] == var[1]]
            if selected and rule != "clang_cfg_allocation_result_used_without_null_check":
                proved = all(o["status"] == "discharged" for o in selected)
                reason = (
                    "all_exits_release_or_transfer_same_object"
                    if proved
                    else "ownership_alias_or_exit_coverage_unclosed"
                )
                if not proved and rule == "clang_cfg_fd_open_return_without_close":
                    position = re.search(r":(\d+)$", str(issue.get("location") or ""))
                    exit_line = int(issue.get("line") or (position[1] if position else 0))
                    exits = [e for o in selected for e in o["exits"] if e["exit_line"] == exit_line]
                    proved = bool(exits) and all(
                        e["complete"] and e["state"] == "not_acquired" for e in exits
                    )
                    if proved:
                        reason = "reported_exit_is_acquisition_failure_branch"
            elif rule == "clang_cfg_allocation_result_used_without_null_check":
                # All source objects and all uses must be closed. This deliberately
                # refuses to prove a report about one object from another's guard.
                position = re.search(r":(\d+)$", str(issue.get("location") or ""))
                sink_line = int(issue.get("line") or (position[1] if position else 0))
                sink_uses = [u for u in analysis["uses"] if u["line"] == sink_line]
                proved = (
                    bool(sink_uses)
                    and analysis["complete"]
                    and not analysis["gaps"]
                    and all(u["non_null"] for u in analysis["uses"])
                )
                reason = (
                    "allocation_guards_dominate_all_object_uses"
                    if proved
                    else "allocation_guard_coverage_unclosed"
                )
        if (
            not proved
            and kind in {"auto", "guard_bounds"}
            and rule == "clang_cfg_unbounded_count_indexes_fixed_array"
            and category in {"bounds", "out_of_bounds_write", "buffer_overflow"}
        ):
            proved = self._fixed_array_bounds(
                fn, issue, source, str(data.get("preprocessor") or "")
            )
            reason = (
                "fixed_array_access_proved_in_range"
                if proved
                else "numeric_conversion_overflow_or_path_unclosed"
            )
            if not proved:
                proved = self._dynamic_array_bounds(fn, issue, source, functions)
                if proved:
                    reason = "dynamic_calloc_capacity_matches_unchanged_loop_bound"
            if not proved:
                witness = self._constant_bad_access(fn, issue, source)
                if witness:
                    result.update(status="contradicted", counterexample=witness)
                    reason = "unconditional_constant_index_outside_object"
        if (
            not proved
            and kind in {"auto", "lock_coverage"}
            and category in {"race", "unsynchronized_shared_state"}
        ):
            reason = "shared_object_identity_not_resolved"
            target = str(issue.get("source") or "")
            globals_ = self._globals(data)
            matches = [
                uid
                for uid, n in globals_.items()
                if n.get("name") == target
                and n.get("storageClass") == "static"
                and re.fullmatch(
                    r"(?:(?:unsigned|signed) )?(?:char|short(?: int)?|int|long(?: long)?(?: int)?|float|double|long double|_Bool|bool)",
                    str(
                        n.get("type", {}).get("desugaredQualType")
                        or n.get("type", {}).get("qualType")
                        or ""
                    ),
                )
            ]
            if len(matches) == 1 and all(
                n.get("kind") not in {"CXXMethodDecl", "LambdaExpr", "BlockDecl"}
                for n in walk_ast(data["ast"])
            ):
                all_refs = sum(
                    symbol(n) == matches[0] and n.get("kind") == "DeclRefExpr"
                    for n in walk_ast(data["ast"])
                )
                fn_refs = sum(
                    symbol(n) == matches[0] and n.get("kind") == "DeclRefExpr"
                    for f in functions.values()
                    for n in walk_ast(f)
                )
                if all_refs != fn_refs:
                    result["reason"] = "global_escape_or_unresolved_function_access"
                    issue.setdefault("review_claim_checks", []).append(deepcopy(result))
                    return result
                lock_details: Dict[str, Any] = {}
                from .lock_coverage import lock_constants

                proved = self._all_accesses_locked(
                    matches[0],
                    functions,
                    functions_checked,
                    {uid for uid, n in globals_.items() if n.get("storageClass") == "static"},
                    data["ast"],
                    lock_constants(data),
                    lock_details,
                )
                result["coverage"]["lock_analysis"] = lock_details
                reason = (
                    "all_static_object_accesses_hold_compatible_verified_lock"
                    if proved
                    else "lock_or_conflicting_access_coverage_unclosed"
                )
        result.update(
            reason=reason,
            checked_functions=sorted(functions_checked),
            build_identity=data["fact_store_id"],
            evidence_refs=[data["fact_store_id"]],
        )
        # Every helper traversed by the checker needs its own CFG identity.
        if proved and not type_only:
            for checked_name in functions_checked:
                matches_cfg = [
                    g
                    for g in data["cfg"]
                    if re.search(r"\b" + re.escape(checked_name) + r"\s*\(", g["signature"])
                ]
                if len(matches_cfg) != 1 or not matches_cfg[0]["complete"]:
                    proved = False
                    result["reason"] = "helper_cfg_incomplete_or_ambiguous"
        if self.registry.version != registry_version:
            proved = False
            result["reason"] = "contracts_changed_during_review"
        if proved and issue.get("analysis_scope") != "conditional_source_branch":
            result.update(status="supported", reason=reason)
            result["coverage"].update(complete=True, scope="candidate_obligation_in_current_build")
            result["coverage"].update(
                path_coverage_required=not type_only,
                basis=(
                    (
                        "compiler_call_operand"
                        if type_only and category == "format_string"
                        else "complete_type_definition"
                    )
                    if type_only
                    else "complete_function_control_flow"
                ),
            )
            result["coverage"]["functions"] = [
                {
                    "function": g["signature"],
                    "cfg_identity": g["function_local_id"],
                    "exits": [b["qualified_id"] for b in g["blocks"] if "EXIT" in b["label"]],
                    "edge_count": sum(len(b["successors"]) for b in g["blocks"]),
                    "cfg_complete": g["complete"],
                    "used_for_path_proof": not type_only,
                }
                for g in data["cfg"]
                if any(
                    re.search(r"\b" + re.escape(f) + r"\s*\(", g["signature"])
                    for f in functions_checked
                )
            ]
            receipt = {
                "checker_version": CHECKER_VERSION,
                "candidate_binding": _binding(issue),
                "contract_version": registry_version,
                "fact_store_id": data["fact_store_id"],
                "dependencies": data["dependencies"],
                "compiler_environment": data["compiler_environment"],
                "preprocessor_probe": data["preprocessor_probe"],
                "reason": reason,
                "coverage": result["coverage"],
                "checked_functions": sorted(functions_checked),
                "native_build_context": (data.get("raii_native_facts") or {}).get(
                    "build_context", {}
                ),
            }
            if receipt["native_build_context"]:
                from ...retrieval.raii_lifecycle import native_tool_dependencies

                receipt["dependencies"] = {
                    **receipt["dependencies"],
                    **native_tool_dependencies(receipt["native_build_context"]),
                }
            receipt["signature"] = hmac.new(
                _RECEIPT_KEY, digest(receipt).encode(), hashlib.sha256
            ).hexdigest()
            issue["review_checked_proof"] = _ReviewReceipt(receipt, self.registry)
            if reason == "reported_owned_field_absent_in_complete_type" and member is not None:
                # Pointer type alone is not an ownership finding. Require an
                # actual member assignment from a pointer-returning call in
                # the object's factory, and group the parent's cleanup issue.
                proposals = issue.setdefault("review_related_proposals", [])
                initializers = [n for n in walk_ast(variables[0]) if n.get("kind") == "CallExpr"]
                factory = (
                    functions.get(call(initializers[0])[0]) if len(initializers) == 1 else None
                )
                affected: set[str] = set()
                if factory:
                    returned = {
                        symbol(n["inner"][0])
                        for n in walk_ast(factory)
                        if n.get("kind") == "ReturnStmt"
                        and n.get("inner")
                        and symbol(n["inner"][0])
                    }
                    field_names_by_id = {
                        n["id"]: n.get("name", "")
                        for n in records[0].get("inner", [])
                        if n.get("kind") == "FieldDecl"
                    }
                    for event in walk_ast(factory):
                        children = event.get("inner", [])
                        if (
                            event.get("kind") != "BinaryOperator"
                            or event.get("opcode") != "="
                            or len(children) != 2
                        ):
                            continue
                        left = strip(children[0])
                        if (
                            left.get("kind") != "MemberExpr"
                            or symbol(left.get("inner", [{}])[0]) not in returned
                        ):
                            continue
                        field_id = left.get("referencedMemberDecl")
                        if field_id in field_names_by_id and any(
                            n.get("kind") == "CallExpr"
                            and str(n.get("type", {}).get("qualType", "")).endswith("*")
                            for n in walk_ast(children[1])
                        ):
                            affected.add(str(field_names_by_id[field_id]))
                if affected:
                    subject = member[1]
                    members = ", ".join(f"{subject}->{field}" for field in sorted(affected))
                    proposal = {
                        "file": data["source"],
                        "line": int(issue.get("line") or 0),
                        "function": name,
                        "category": "memory_leak",
                        "source": subject,
                        "sink": str(issue.get("sink") or "parent object release"),
                        "description": f"对象构造函数对真实成员 {members} 赋入了调用返回的指针；父对象释放时需核查这些成员的所有权和清理路径。",
                        "analysis_scope": "current_build",
                        "trigger_condition": "成员持有独立分配且未释放或转移所有权",
                        "evidence_refs": [data["fact_store_id"]],
                        "parent_fact_store_id": data["fact_store_id"],
                    }
                    if proposal not in proposals:
                        proposals.append(proposal)
        issue.setdefault("review_claim_checks", []).append(deepcopy(result))
        return result

    def _dynamic_array_bounds(
        self,
        fn: Dict[str, Any],
        issue: Dict[str, Any],
        source: str,
        functions: Optional[Dict[str, Any]] = None,
    ) -> bool:
        from ...retrieval.lifecycle_analysis import unwrap, invocation

        position = re.search(r":(\d+)$", str(issue.get("location") or ""))
        target_line = int(issue.get("line") or (position[1] if position else 0))
        nodes = list(walk_ast(fn))
        parents = {str(c.get("id")): n for n in nodes for c in n.get("inner", []) if c.get("id")}
        declarations = {
            str(n.get("id")): n for n in nodes if n.get("kind") in {"VarDecl", "ParmVarDecl"}
        }
        accesses = [
            n
            for n in nodes
            if n.get("kind") == "ArraySubscriptExpr" and line_of(n, source) == target_line
        ]
        if not accesses or self._unsupported_lifetime_effects(fn):
            return False
        for access in accesses:
            array, subscript = access.get("inner", [{}, {}])
            decl = declarations.get(symbol(array), {})
            initializer = decl.get("inner", [])
            if len(initializer) != 1:
                return False
            api, args = invocation(unwrap(initializer[0]))
            contracts = [
                c
                for c in self.registry.find(api, "calloc")
                if not (api in (functions or {}) and c.source.startswith("builtin"))
            ]
            if len(args) != 2 or not contracts or not all(c.effects_trusted for c in contracts):
                return False
            # Require the actual element-size operand and reviewed extent
            # mapping, not a suggestive name or a pointer declaration alone.
            from ...semantics.contracts import ObjectBinding

            if any(
                [ObjectBinding.from_value(v) for v in c.protocol.get("allocation_extent", [])]
                != [ObjectBinding("argument", 0), ObjectBinding("argument", 1)]
                for c in contracts
            ):
                return False
            size = strip(args[1])
            if size.get("kind") != "UnaryExprOrTypeTraitExpr" or size.get("name") != "sizeof":
                return False
            pointee = (
                str(
                    decl.get("type", {}).get("desugaredQualType")
                    or decl.get("type", {}).get("qualType", "")
                )
                .rstrip()
                .removesuffix("*")
                .strip()
            )
            element = size.get("argType", {}).get("desugaredQualType") or size.get(
                "argType", {}
            ).get("qualType", "")
            if not element or element != pointee:
                return False
            count = args[0]
            if count.get("kind") == "ImplicitCastExpr" and count.get("castKind") == "IntegralCast":
                # calloc's size_t widening is legal only for an unsigned source;
                # narrowing or signed conversion requires an explicit range.
                child = strip(count.get("inner", [{}])[0])
                ty = child.get("type", {})
                if (ty.get("desugaredQualType") or ty.get("qualType")) != "unsigned int":
                    return False
                count = child
            count_id = symbol(count)
            if count_id not in declarations:
                return False
            if declarations[count_id].get("storageClass") == "static" or "volatile" in declarations[
                count_id
            ].get("type", {}).get("qualType", ""):
                return False
            ancestor = access
            while str(ancestor.get("id")) in parents and ancestor.get("kind") != "ForStmt":
                ancestor = parents[str(ancestor["id"])]
            parts = ancestor.get("inner", [])
            if ancestor.get("kind") != "ForStmt" or len(parts) != 5:
                return False
            loop_decls = parts[0].get("inner", [])
            if len(loop_decls) != 1 or not loop_decls[0].get("inner"):
                return False
            iteration = loop_decls[0]
            index_id = str(iteration.get("id"))
            condition, step = strip(parts[2]), strip(parts[3])
            operands = condition.get("inner", [])
            ty = iteration.get("type", {})
            count_type = declarations[count_id].get("type", {})
            if not (
                integer(iteration["inner"][-1]) == 0
                and symbol(subscript) == index_id
                and condition.get("opcode") == "<"
                and len(operands) == 2
                and symbol(operands[0]) == index_id
                and symbol(operands[1]) == count_id
                and step.get("opcode") == "++"
                and symbol(step.get("inner", [{}])[0]) == index_id
                and (ty.get("desugaredQualType") or ty.get("qualType")) == "unsigned int"
                and (count_type.get("desugaredQualType") or count_type.get("qualType"))
                == "unsigned int"
            ):
                return False
            watched = {symbol(array), index_id, count_id}
            loop_end = line_of({"loc": ancestor.get("range", {}).get("end", {})}, source)
            for node in nodes:
                if (
                    node is step
                    or node.get("kind") == "UnaryOperator"
                    and node.get("id") == step.get("id")
                ):
                    continue
                children = node.get("inner", [])
                if node.get("kind") in {"GotoStmt", "IndirectGotoStmt", "GCCAsmStmt", "MSAsmStmt"}:
                    return False
                if loop_end and line_of(node, source) > loop_end:
                    # Cleanup after the entire loop cannot change an earlier
                    # access. Mutations later inside the loop still affect its
                    # next iteration and must be rejected below.
                    continue
                if children and (
                    node.get("kind") == "CompoundAssignOperator"
                    or node.get("kind") == "BinaryOperator"
                    and node.get("opcode") == "="
                    or node.get("kind") == "UnaryOperator"
                    and node.get("opcode") in {"++", "--", "&"}
                ):
                    if symbol(children[0]) in watched:
                        return False
                if node.get("kind") == "CallExpr" and line_of(node, source) < target_line:
                    if any(symbol(a) == symbol(array) for a in call(node)[1]):
                        return False
        return True

    def _reported_descriptor_exit(
        self,
        fn: Dict[str, Any],
        issue: Dict[str, Any],
        source: str,
        functions: Dict[str, Dict[str, Any]],
    ) -> tuple[bool, str]:
        from ...semantics.contract_conditions import compare

        subject = re.search(r"\b([A-Za-z_]\w*)\s*=", str(issue.get("source") or ""))
        position = re.search(r":(\d+)$", str(issue.get("location") or ""))
        target_line = int(issue.get("line") or (position[1] if position else 0))
        nodes = list(walk_ast(fn))
        decls = [
            n
            for n in nodes
            if n.get("kind") == "VarDecl" and subject and n.get("name") == subject[1]
        ]
        exits = [
            n for n in nodes if n.get("kind") == "ReturnStmt" and line_of(n, source) == target_line
        ]
        if len(decls) != 1 or len(exits) != 1 or len(decls[0].get("inner", [])) != 1:
            return False, "descriptor_or_exit_identity_unclosed"
        decl, target = decls[0], exits[0]
        uid = str(decl["id"])
        api, _ = call(decl["inner"][0])
        contracts = self.registry.find(api, "io_acquire")
        if not contracts or not all(
            c.effects_trusted and c.carrier.kind == "return" and c.resource_family == "descriptor"
            for c in contracts
        ):
            return False, "descriptor_contract_unclosed"
        if api in functions and all(c.source.startswith("builtin") for c in contracts):
            return False, "project_api_requires_own_contract"
        for node in nodes:
            children = node.get("inner", [])
            if children and (
                node.get("kind") == "CompoundAssignOperator"
                or node.get("kind") == "BinaryOperator"
                and node.get("opcode") == "="
                or node.get("kind") == "UnaryOperator"
                and node.get("opcode") in {"&", "++", "--"}
            ):
                if symbol(children[0]) == uid:
                    return False, "descriptor_assignment_version_unclosed"
        if target.get("inner") and symbol(target["inner"][0]) == uid:
            return True, "reported_exit_returns_descriptor_to_caller"
        parents = {str(c.get("id")): n for n in nodes for c in n.get("inner", []) if c.get("id")}
        child = target
        while str(child.get("id")) in parents:
            parent = parents[str(child["id"])]
            parts = parent.get("inner", [])
            if parent.get("kind") == "IfStmt" and len(parts) in {2, 3} and child is parts[1]:
                condition = strip(parts[0])
                operands = condition.get("inner", [])
                if (
                    len(operands) == 2
                    and symbol(operands[0]) == uid
                    and (
                        condition.get("opcode") == "<"
                        and integer(operands[1]) == 0
                        or condition.get("opcode") == "=="
                        and integer(operands[1]) == -1
                    )
                ):
                    effects = [
                        e for c in contracts for e in c.effect_cases if e.get("effect") == "applies"
                    ]
                    if effects and all(
                        e.get("when") == compare({"kind": "return"}, ">=", 0) for e in effects
                    ):
                        return True, "reported_exit_is_acquisition_failure_branch"
            child = parent
        return False, "descriptor_acquisition_or_exit_coverage_unclosed"

    def _same_copy_extent(
        self,
        fn: Dict[str, Any],
        issue: Dict[str, Any],
        source: str,
        functions: Dict[str, Dict[str, Any]],
    ) -> bool:
        from ...retrieval.lifecycle_analysis import expression, unwrap

        position = re.search(r":(\d+)$", str(issue.get("location") or ""))
        target_line = int(issue.get("line") or (position[1] if position else 0))
        copies = [
            n
            for n in walk_ast(fn)
            if call(n)[0] in {"memcpy", "memmove"}
            and call(n)[0] not in functions
            and line_of(n, source) == target_line
        ]
        if not copies:
            return False
        declarations = {str(n.get("id")): n for n in walk_ast(fn) if n.get("kind") == "VarDecl"}
        for node in copies:
            _, arguments = call(node)
            if len(arguments) != 3:
                return False
            target = symbol(arguments[0])
            declaration = declarations.get(target, {})
            initializers = declaration.get("inner", [])
            if len(initializers) != 1:
                return False
            called, args = call(unwrap(initializers[0]))
            contracts = self.registry.find(called)
            if not called or not any(
                c.effects_trusted and c.role in {"allocator", "calloc"} for c in contracts
            ):
                return False
            if called in functions and all(c.source.startswith("builtin") for c in contracts):
                return False
            extent = self.registry.allocation_extent(called, [expression(a) for a in args])
            length = expression(arguments[2])
            if not extent or re.sub(r"\s+", "", extent) != re.sub(r"\s+", "", length):
                return False
            dependencies = {
                symbol(a) for a in walk_ast(arguments[2]) if a.get("kind") == "DeclRefExpr"
            } | {target}
            locals_and_parameters = {
                str(n.get("id")): n
                for n in walk_ast(fn)
                if n.get("kind") in {"VarDecl", "ParmVarDecl"}
            }
            if any(
                d not in locals_and_parameters
                or locals_and_parameters[d].get("storageClass") == "static"
                or "volatile" in locals_and_parameters[d].get("type", {}).get("qualType", "")
                for d in dependencies
            ):
                return False
            if self._unsupported_lifetime_effects(fn):
                return False
            for other in walk_ast(fn):
                children = other.get("inner", [])
                if (
                    other.get("kind") in {"BinaryOperator", "CompoundAssignOperator"}
                    and other.get("opcode")
                    in {"=", "+=", "-=", "*=", "/=", "<<=", ">>=", "|=", "&=", "^=", "%="}
                    or other.get("kind") == "UnaryOperator"
                    and other.get("opcode") in {"++", "--", "&"}
                ):
                    if children and symbol(children[0]) in dependencies:
                        return False
            if any(
                n.get("kind") in {"MemberExpr", "CallExpr", "ArraySubscriptExpr"}
                for n in walk_ast(arguments[2])
            ):
                return False
        return True

    @staticmethod
    def _globals(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        # File-scope declarations only. Locals and parameters cannot prove
        # durable ownership or complete global access coverage.
        return {n["id"]: n for n in data["ast"].get("inner", []) if n.get("kind") == "VarDecl"}

    @staticmethod
    def _body(fn: Dict[str, Any]) -> Dict[str, Any]:
        return next((c for c in fn.get("inner", []) if c.get("kind") == "CompoundStmt"), {})

    @staticmethod
    def _unsupported_lifetime_effects(node: Dict[str, Any]) -> bool:
        # Implicit destruction, overloaded operations and assembly are not
        # represented by this C ownership interpreter's transfer semantics.
        return any(
            str(n.get("kind", "")).startswith(("CXX", "ObjC"))
            or n.get("kind") in {"GCCAsmStmt", "MSAsmStmt", "LambdaExpr", "BlockExpr"}
            for n in walk_ast(node)
        )

    @staticmethod
    def _side_effects(node: Dict[str, Any]) -> bool:
        return ReviewClaimChecker._unsupported_lifetime_effects(node) or any(
            n.get("kind") in {"CallExpr", "CXXMemberCallExpr", "CompoundAssignOperator"}
            or (n.get("kind") == "BinaryOperator" and n.get("opcode") == "=")
            or (n.get("kind") == "UnaryOperator" and n.get("opcode") in {"++", "--"})
            for n in walk_ast(node)
        )

    @staticmethod
    def _constant_bad_access(
        fn: Dict[str, Any], issue: Dict[str, Any], source: str
    ) -> Optional[Dict[str, Any]]:
        arrays: Dict[str, int] = {}
        for statement in ReviewClaimChecker._body(fn).get("inner", []):
            if statement.get("kind") == "DeclStmt":
                if ReviewClaimChecker._side_effects(statement):
                    return None
                for node in statement.get("inner", []):
                    bound = re.fullmatch(
                        r"(?:unsigned |signed )?(?:char|int)\s*\[(\d+)\]",
                        node.get("type", {}).get("qualType", ""),
                    )
                    if bound:
                        arrays[str(node["id"])] = int(bound[1])
                continue
            # Only a straight-line first access supplies a feasible witness.
            # A syntactic out-of-range expression under an unknown branch does not.
            if statement.get("kind") != "BinaryOperator" or statement.get("opcode") != "=":
                return None
            children = statement.get("inner", [])
            if len(children) != 2 or integer(children[1]) is None:
                return None
            left = strip(children[0]) if children else {}
            if left.get("kind") != "ArraySubscriptExpr" or line_of(left, source) != int(
                issue.get("line") or 0
            ):
                return None
            operands = left.get("inner", [])
            if len(operands) != 2:
                return None
            capacity, index = arrays.get(symbol(operands[0])), integer(operands[1])
            if capacity is not None and index is not None and not 0 <= index < capacity:
                return {
                    "function": fn.get("name"),
                    "node_id": left.get("id"),
                    "line": line_of(left, source),
                    "index": index,
                    "capacity": capacity,
                    "scope": "one_unconditional_access_in_current_build",
                }
            return None
        return None

    @staticmethod
    def _fixed_array_bounds(
        fn: Dict[str, Any], issue: Dict[str, Any], source: str, preprocessor: str = ""
    ) -> bool:
        target_line = int(issue.get("line") or issue.get("start_line") or 0)
        if not target_line:
            match = re.search(r":(\d+)$", str(issue.get("location") or ""))
            target_line = int(match[1]) if match else 0
        arrays = {}
        for node in walk_ast(fn):
            if node.get("kind") == "VarDecl":
                match = re.search(r"\[(\d+)\]$", node.get("type", {}).get("qualType", ""))
                if match:
                    arrays[node["id"]] = int(match[1])
        accesses = [
            n
            for n in walk_ast(fn)
            if n.get("kind") == "ArraySubscriptExpr" and line_of(n, source) == target_line
        ]
        if not accesses:
            return False
        parents = {
            str(c.get("id")): n for n in walk_ast(fn) for c in n.get("inner", []) if c.get("id")
        }

        def induction(access: Dict[str, Any], variable: str, capacity: int) -> bool:
            ancestor = access
            while str(ancestor.get("id")) in parents:
                ancestor = parents[str(ancestor["id"])]
                if ancestor.get("kind") != "ForStmt":
                    continue
                parts = ancestor.get("inner", [])
                if len(parts) != 5 or parts[0].get("kind") != "DeclStmt":
                    return False
                decls = parts[0].get("inner", [])
                if len(decls) != 1 or decls[0].get("id") != variable:
                    return False
                init = decls[0].get("inner", [])
                start = integer(init[-1]) if init else None
                cond, step = strip(parts[2]), strip(parts[3])
                operands = cond.get("inner", [])
                stop = integer(operands[1]) if len(operands) == 2 else None
                if cond.get("opcode") != "<" or not operands or symbol(operands[0]) != variable:
                    return False
                if (
                    step.get("kind") != "UnaryOperator"
                    or step.get("opcode") != "++"
                    or symbol(step.get("inner", [{}])[0]) != variable
                ):
                    return False
                maximum = re.search(r"^#define __INT_MAX__ (\d+)", preprocessor, re.M)
                ty = decls[0].get("type", {}).get("qualType")
                if not maximum or ty not in {"int", "unsigned int"}:
                    return False
                max_value = int(maximum[1]) * (2 if ty == "unsigned int" else 1) + (
                    1 if ty == "unsigned int" else 0
                )
                if (
                    start is None
                    or stop is None
                    or not 0 <= start < stop <= min(capacity, max_value)
                ):
                    return False
                for node in walk_ast(parts[4]):
                    children = node.get("inner", [])
                    if node.get("kind") in {
                        "CallExpr",
                        "GotoStmt",
                        "IndirectGotoStmt",
                        "GCCAsmStmt",
                        "MSAsmStmt",
                    } or ReviewClaimChecker._unsupported_lifetime_effects(node):
                        return False
                    if node.get("kind") in {
                        "BinaryOperator",
                        "CompoundAssignOperator",
                    } and node.get("opcode") in {
                        "=",
                        "+=",
                        "-=",
                        "*=",
                        "/=",
                        "%=",
                        "<<=",
                        ">>=",
                        "&=",
                        "|=",
                        "^=",
                    }:
                        if children and symbol(children[0]) == variable:
                            return False
                    if (
                        node.get("kind") == "UnaryOperator"
                        and node.get("opcode") in {"&", "++", "--"}
                        and children
                        and symbol(children[0]) == variable
                    ):
                        return False
                return True
            return False

        # The canonical induction is checked against target integer limits;
        # symbolic arithmetic, conversions and unsupported aliases stay unknown.
        for access in accesses:
            args = access.get("inner", [])
            if len(args) != 2 or symbol(args[0]) not in arrays:
                return False
            index = integer(args[1])
            capacity = arrays[symbol(args[0])]
            if index is None and not induction(access, symbol(args[1]), capacity):
                return False
            if index is not None and not 0 <= index < capacity:
                return False
        return True

    def _all_accesses_locked(
        self,
        subject: str,
        functions: Dict[str, Dict[str, Any]],
        checked: set[str],
        global_locks: set[str],
        ast: Dict[str, Any],
        constants: Optional[Dict[str, int]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        from .lock_coverage import lock_coverage

        return lock_coverage(
            subject, functions, checked, global_locks, ast, self.registry, constants or {}, details
        )


def guard_coverage(
    call_sites: Iterable[Dict[str, Any]],
    *,
    inventory_complete: bool,
    unresolved_indirect_calls: bool,
    external_entry_contract_complete: bool,
) -> Dict[str, Any]:
    """Summarize checked coverage; caller counts never supply authority."""
    rows = []
    for raw in call_sites:
        row = {k: raw.get(k) for k in ("caller", "callee", "location")}
        status = "unknown"
        evidence = raw.get("checked_path")
        signature = evidence.get("signature", "") if isinstance(evidence, dict) else ""
        payload = (
            {k: v for k, v in evidence.items() if k != "signature"}
            if isinstance(evidence, dict)
            else {}
        )
        valid = bool(signature) and hmac.compare_digest(
            str(signature),
            hmac.new(_RECEIPT_KEY, digest(payload).encode(), hashlib.sha256).hexdigest(),
        )
        if valid and isinstance(evidence, dict) and evidence.get("complete") is True:
            if evidence.get("unreachable") is True:
                status = "unreachable_proved"
            elif evidence.get("parameter_mapping_complete") is True:
                if evidence.get("guard_dominates_sink") is True:
                    status = "guarded"
                elif evidence.get("feasible_unguarded_path") is True:
                    status = "unguarded"
        row["status"] = status
        rows.append(row)
    complete = bool(
        rows
        and inventory_complete
        and not unresolved_indirect_calls
        and external_entry_contract_complete
        and all(r["status"] != "unknown" for r in rows)
    )
    return {
        "rows": rows,
        "complete": complete,
        "known_call_site_count": len(rows),
        "unresolved_indirect_calls": unresolved_indirect_calls,
        "external_entry_contract_complete": external_entry_contract_complete,
        "all_paths_guarded": complete
        and all(r["status"] in {"guarded", "unreachable_proved"} for r in rows),
    }


def check_guard_call_sites(
    store: CompleteFactStore, uid: str, callee: str, parameter: int, lower: int, upper: int
) -> Dict[str, Any]:
    """A narrow numeric-contract coverage table, derived from compiler AST.

    Constant actual arguments can discharge the specified call-site contract.
    Symbolic/indirect calls and external entrances stay unknown. This table is
    diagnostic and cannot mint a candidate-level rejection receipt.
    """
    data = store.load(uid)
    rows: list[Dict[str, Any]] = []
    unresolved = True
    if data.get("complete") and store.is_trusted(uid) and parameter >= 0 and lower < upper:
        unresolved = False
        source = Path(data["source"]).read_text(encoding="utf-8")
        for name, fn in ReviewClaimChecker._functions(data).items():
            for node in walk_ast(fn):
                if node.get("kind") != "CallExpr":
                    continue
                target, args = call(node)
                if not target:
                    unresolved = True
                if target != callee:
                    continue
                row: Dict[str, Any] = {
                    "caller": name,
                    "callee": callee,
                    "location": f'{data["source"]}:{line_of(node, source)}',
                }
                value = integer(args[parameter]) if len(args) > parameter else None
                if value is not None and lower <= value < upper:
                    proof = {
                        "complete": True,
                        "parameter_mapping_complete": True,
                        "guard_dominates_sink": True,
                        "fact_store_id": uid,
                        "caller": name,
                        "location": row["location"],
                        "contract": {"parameter": parameter, "lower": lower, "upper": upper},
                    }
                    proof["signature"] = hmac.new(
                        _RECEIPT_KEY, digest(proof).encode(), hashlib.sha256
                    ).hexdigest()
                    row["checked_path"] = proof
                rows.append(row)
    result = guard_coverage(
        rows,
        inventory_complete=False,
        unresolved_indirect_calls=unresolved,
        external_entry_contract_complete=False,
    )
    result.update(
        fact_store_id=uid,
        contract={"parameter": parameter, "lower": lower, "upper": upper},
        reason="translation_unit_inventory_does_not_close_external_entry_contract",
    )
    return result
