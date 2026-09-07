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

CHECKER_VERSION = "zscope.review-checkers.v1"
RULE_CONTRACT_REVISIONS = {
    "clang_cfg_parent_release_without_owned_member_cleanup": 1,
    "clang_cfg_acquire_without_release_on_exit": 1,
    "clang_cfg_unchecked_insert_after_ownership_handoff": 1,
    "clang_cfg_unbounded_count_indexes_fixed_array": 1,
}
_RECEIPT_KEY = secrets.token_bytes(32)
_TRANSPARENT = {"ImplicitCastExpr", "ParenExpr", "ExprWithCleanups", "ConstantExpr"}


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
        ty = node.get("type", {}).get("qualType", "")
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
        if "unsigned" in str(node.get("type", {}).get("qualType") or ""):
            return None
        value = integer(node.get("inner", [{}])[0])
        return -value if value is not None else None
    return None


def _binding(issue: Dict[str, Any]) -> str:
    return digest(
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
            )
        }
    )


def checked_receipt(issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate driver-issued authority, including current dependency bytes."""
    receipt = issue.get("review_checked_proof")
    if not isinstance(receipt, dict):
        return None
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    expected = hmac.new(_RECEIPT_KEY, digest(payload).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(receipt.get("signature") or "")):
        return None
    if receipt.get("candidate_binding") != _binding(issue):
        return None
    if receipt.get("compiler_environment") != CompleteFactStore.compiler_environment():
        return None
    try:
        deps = receipt["dependencies"]
        if not deps or CompleteFactStore._hash_files(deps) != deps:
            return None
    except (KeyError, OSError):
        return None
    return receipt


class ReviewClaimChecker:
    def __init__(self, store: CompleteFactStore):
        self.store = store

    def prepare(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        file = str(issue.get("file") or issue.get("file_path") or "")
        if not file:
            file = re.sub(r":\d+(?::\d+)?$", "", str(issue.get("location") or ""))
        descriptor = self.store.collect(file)
        issue["review_fact_store"] = descriptor
        if descriptor.get("complete"):
            data = self.store.load(descriptor["fact_store_id"])
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
                        if not re.search(r"LOCK|GUARD|CHECK|ASSERT|BOUND", risk["name"], re.I):
                            continue
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
        grouped: Dict[str, list[Dict[str, Any]]] = {}
        for n in walk_ast(data["ast"]):
            if n.get("kind") == "FunctionDecl" and any(
                c.get("kind") == "CompoundStmt" for c in n.get("inner", [])
            ):
                grouped.setdefault(str(n.get("name")), []).append(n)
        return {name: nodes[0] for name, nodes in grouped.items() if len(nodes) == 1}

    def check(self, issue: Dict[str, Any], kind: str = "auto") -> Dict[str, Any]:
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
        if (
            rule in RULE_CONTRACT_REVISIONS
            and issue.get("rule_revision") != RULE_CONTRACT_REVISIONS[rule]
        ):
            result["reason"] = "unqualified_rule_contract_revision"
            issue.setdefault("review_claim_checks", []).append(deepcopy(result))
            return result
        reason = "unsupported_candidate_obligation"
        proved = False
        if (
            kind in {"auto", "type_identity"}
            and rule == "clang_cfg_parent_release_without_owned_member_cleanup"
        ):
            reason = "owned_member_identity_not_resolved"
            member = re.search(
                r"common owned member [`']?(\w+)->(\w+)", str(issue.get("description") or "")
            )
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
            and kind in {"auto", "ownership_cleanup"}
            and category == "memory_leak"
            and rule
            in {
                "clang_cfg_unchecked_insert_after_ownership_handoff",
                "clang_cfg_acquire_without_release_on_exit",
            }
        ):
            reason = "allocation_subject_not_resolved"
            # The source allocation and tracked object must be identified from the
            # actual declaration, not from a model-proposed substitute object.
            source_text = str(issue.get("source") or "")
            var = re.search(r"\b(\w+)\s*(?:allocated\b|=)", source_text)
            if not var and rule == "clang_cfg_acquire_without_release_on_exit":
                var = re.search(
                    r"^`(\w+)` is acquired from `\w+`", str(issue.get("description") or "")
                )
            if var:
                declarations = [
                    n
                    for n in walk_ast(fn)
                    if n.get("kind") == "VarDecl" and n.get("name") == var[1]
                ]
                if len(declarations) == 1:
                    subject = str(declarations[0]["id"])
                    globals_ = self._globals(data)
                    closed = self._ownership_paths(
                        fn, subject, functions, globals_, functions_checked
                    )
                    proved = closed is True
                    reason = (
                        "all_relevant_exits_release_or_transfer_same_object"
                        if proved
                        else "ownership_alias_or_exit_coverage_unclosed"
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
                if n.get("name") == target and n.get("storageClass") == "static"
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
                proved = self._all_accesses_locked(
                    matches[0],
                    functions,
                    functions_checked,
                    {uid for uid, n in globals_.items() if n.get("storageClass") == "static"},
                    data["ast"],
                )
                reason = (
                    "all_static_object_accesses_hold_same_verified_mutex"
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
        if proved and issue.get("analysis_scope") != "conditional_source_branch":
            result.update(status="supported", reason=reason)
            result["coverage"].update(complete=True, scope="candidate_obligation_in_current_build")
            result["coverage"].update(
                path_coverage_required=not type_only,
                basis="complete_type_definition" if type_only else "complete_function_control_flow",
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
                "fact_store_id": data["fact_store_id"],
                "dependencies": data["dependencies"],
                "compiler_environment": data["compiler_environment"],
                "reason": reason,
                "coverage": result["coverage"],
                "checked_functions": sorted(functions_checked),
            }
            receipt["signature"] = hmac.new(
                _RECEIPT_KEY, digest(receipt).encode(), hashlib.sha256
            ).hexdigest()
            issue["review_checked_proof"] = receipt
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

    @staticmethod
    def _globals(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        # File-scope declarations only. Locals and parameters cannot prove
        # durable ownership or complete global access coverage.
        return {n["id"]: n for n in data["ast"].get("inner", []) if n.get("kind") == "VarDecl"}

    @staticmethod
    def _body(fn: Dict[str, Any]) -> Dict[str, Any]:
        return next((c for c in fn.get("inner", []) if c.get("kind") == "CompoundStmt"), {})

    def _transfers(
        self,
        name: str,
        index: int,
        functions: Dict[str, Dict[str, Any]],
        globals_: Dict[str, Any],
        checked: set[str],
    ) -> bool:
        fn = functions.get(name)
        if not fn or name in checked:
            return False
        if self._unsupported_lifetime_effects(fn):
            return False
        params = [n for n in fn.get("inner", []) if n.get("kind") == "ParmVarDecl"]
        if index >= len(params):
            return False
        checked.add(name)
        target = str(params[index]["id"])
        # All paths must commit the same parameter into persistent storage.
        # A void/error-code return by itself says nothing about ownership.
        slots: set[str] = set()
        # Local durable cursors must be unconditionally initialized in the
        # outer block. A declaration in one branch cannot justify another.
        for statement in self._body(fn).get("inner", []):
            if statement.get("kind") == "DeclStmt":
                for var in statement.get("inner", []):
                    init = var.get("inner", [])
                    if (
                        init
                        and symbol(init[-1]).startswith("&")
                        and symbol(init[-1])[1:] in globals_
                    ):
                        slots.add(var["id"])

        def durable(expr: Dict[str, Any]) -> bool:
            key = symbol(expr)
            return key in globals_ or (key.startswith("*") and key[1:] in slots)

        def evaluate(node: Dict[str, Any], owned: bool) -> Optional[list[tuple[bool, bool]]]:
            node = strip(node)
            children = node.get("inner", [])
            k = node.get("kind")
            if k == "CompoundStmt":
                states = [(owned, False)]
                for child in children:
                    next_states = []
                    for state, ended in states:
                        values = [(state, True)] if ended else evaluate(child, state)
                        if values is None:
                            return None
                        next_states.extend(values)
                    states = next_states
                return states
            if k == "DeclStmt":
                for var in children:
                    init = var.get("inner", [])
                    if (
                        init
                        and symbol(init[-1]).startswith("&")
                        and symbol(init[-1])[1:] in globals_
                    ):
                        if var["id"] not in slots:
                            return None
                    elif any(symbol(n) == target for n in walk_ast(var)):
                        return None
                return [(owned, False)]
            if k == "BinaryOperator" and node.get("opcode") == "=" and len(children) == 2:
                left, right = children
                # Once committed, an overwrite could lose the only owner.
                if not owned:
                    return None
                if symbol(right) == target and durable(left):
                    return [(False, False)]
                if symbol(left) == target:
                    return None
                if symbol(left) in slots:
                    # Preserve the invariant that cursor points into the same
                    # durable tree, including cursor = &(*cursor)->left/right.
                    refs = {symbol(n) for n in walk_ast(right) if n.get("kind") == "DeclRefExpr"}
                    if strip(right).get("opcode") != "&" or not refs or not refs.issubset(slots):
                        return None
                if any(n.get("kind") == "CallExpr" for n in walk_ast(node)):
                    return None
                return [(owned, False)]
            if k == "IfStmt" and len(children) in {2, 3}:
                if self._side_effects(children[0]):
                    return None
                a = evaluate(children[1], owned)
                b = evaluate(children[2], owned) if len(children) == 3 else [(owned, False)]
                return None if a is None or b is None else a + b
            if k == "WhileStmt" and len(children) == 2:
                # A tree traversal is allowed only if it does not change
                # ownership and preserves the durable-slot invariant.
                if any(n.get("kind") == "CallExpr" for n in walk_ast(children[0])):
                    return None
                before = set(slots)
                body = evaluate(children[1], owned)
                if body is None or any(s != owned or end for s, end in body) or slots != before:
                    return None
                return [(owned, False)]
            if k == "ReturnStmt":
                if any(n.get("kind") == "CallExpr" for n in walk_ast(node)):
                    return None
                return [(owned, True)]
            if k in {"NullStmt", "IntegerLiteral", "DeclRefExpr"}:
                return [(owned, False)]
            return None

        states = evaluate(self._body(fn), True)
        return bool(states and all(not owned for owned, _ in states))

    def _ownership_paths(
        self,
        fn: Dict[str, Any],
        subject: str,
        functions: Dict[str, Dict[str, Any]],
        globals_: Dict[str, Any],
        checked: set[str],
    ) -> Optional[bool]:
        if self._unsupported_lifetime_effects(fn):
            return None

        # State: not acquired / live / closed; join uses all alternatives.
        def execute(node: Dict[str, Any], state: str) -> Optional[list[tuple[str, bool]]]:
            node = strip(node)
            k, children = node.get("kind"), node.get("inner", [])
            if k == "CompoundStmt":
                states = [(state, False)]
                for child in children:
                    new = []
                    for value, end in states:
                        branch = [(value, True)] if end else execute(child, value)
                        if branch is None:
                            return None
                        new.extend(branch)
                    states = new
                return states
            if k == "DeclStmt":
                if any(n.get("id") == subject for n in children):
                    if len(children) != 1:
                        return None
                    return [("live", False)]
                if any(symbol(n) == subject for n in walk_ast(node)) or self._side_effects(node):
                    return None
                return [(state, False)]
            if k == "IfStmt" and len(children) in {2, 3}:
                cond = strip(children[0])
                if self._side_effects(cond):
                    return None
                null_branch = (
                    cond.get("kind") == "UnaryOperator"
                    and cond.get("opcode") == "!"
                    and symbol(cond.get("inner", [{}])[0]) == subject
                )
                a = execute(children[1], "closed" if null_branch and state == "live" else state)
                b = execute(children[2], state) if len(children) == 3 else [(state, False)]
                return None if a is None or b is None else a + b
            if k == "DoStmt" and len(children) == 2 and integer(children[1]) == 0:
                return execute(children[0], state)
            if k == "ReturnStmt":
                if self._side_effects(node):
                    return None
                if children and symbol(children[0]) == subject:
                    return [("closed", True)]
                if any(symbol(n) == subject for n in walk_ast(node)):
                    return None
                return [(state, True)]
            if k == "CallExpr":
                name, args = call(node)
                positions = [i for i, a in enumerate(args) if symbol(a) == subject]
                if name == "free" and name not in functions and positions == [0]:
                    return [("closed", False)]
                if positions:
                    if len(positions) == 1 and self._transfers(
                        name, positions[0], functions, globals_, checked
                    ):
                        return [("closed", False)]
                    return None
                # Unknown code receiving a field/alias may mutate ownership.
                if any(symbol(n) == subject for n in walk_ast(node)):
                    return None
                return None
            if k == "BinaryOperator" and node.get("opcode") == "=":
                if symbol(children[1]) == subject and symbol(children[0]) in globals_:
                    return [("closed", False)]
                if symbol(children[0]) == subject:
                    return (
                        [(state, False)]
                        if state == "closed" and integer(children[1]) == 0
                        else None
                    )
                if (
                    any(symbol(n) == subject for n in walk_ast(node))
                    or state == "closed"
                    or self._side_effects(children[1])
                ):
                    return None
                return [(state, False)]
            if k in {"NullStmt", "IntegerLiteral"}:
                return [(state, False)]
            return None

        states = execute(self._body(fn), "not_acquired")
        return None if states is None else bool(states and all(s != "live" for s, _ in states))

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
    ) -> bool:
        access_locks: list[set[str]] = []
        used_locks = set()
        for fn in functions.values():
            for node in walk_ast(fn):
                called, arguments = call(node)
                if (
                    called
                    in {"pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_unlock"}
                    and arguments
                ):
                    used_locks.add(
                        symbol(arguments[0])[1:] if symbol(arguments[0]).startswith("&") else ""
                    )
        global_locks &= used_locks
        if sum(
            n.get("kind") == "DeclRefExpr" and symbol(n) in global_locks for n in walk_ast(ast)
        ) != sum(
            n.get("kind") == "DeclRefExpr" and symbol(n) in global_locks
            for fn in functions.values()
            for n in walk_ast(fn)
        ):
            return False

        # A reset/escape in a function that never touches the protected object
        # still invalidates a common-mutex proof. Inspect all mutex references.
        for fn in functions.values():
            parents = {
                str(c.get("id")): n for n in walk_ast(fn) for c in n.get("inner", []) if c.get("id")
            }
            for ref in walk_ast(fn):
                if ref.get("kind") != "DeclRefExpr" or symbol(ref) not in global_locks:
                    continue
                ancestor = ref
                while str(ancestor.get("id")) in parents:
                    ancestor = parents[str(ancestor["id"])]
                    if ancestor.get("kind") == "CallExpr":
                        called, args = call(ancestor)
                        if (
                            called
                            in {
                                "pthread_mutex_lock",
                                "pthread_mutex_trylock",
                                "pthread_mutex_unlock",
                            }
                            and called not in functions
                            and len(args) == 1
                            and symbol(args[0]) == "&" + symbol(ref)
                        ):
                            break
                        return False
                    if ancestor.get("kind") in {
                        "CompoundStmt",
                        "BinaryOperator",
                        "ReturnStmt",
                        "DeclStmt",
                    }:
                        return False
                else:
                    return False

        def lock_call(node: Dict[str, Any]) -> tuple[str, str]:
            name, args = call(node)
            if (
                name in {"pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_unlock"}
                and name not in functions
                and len(args) == 1
                and symbol(args[0]).startswith("&")
                and symbol(args[0])[1:] in global_locks
            ):
                return name, symbol(args[0])
            return "", ""

        def inspect(node: Dict[str, Any], held: set[str]) -> Optional[list[tuple[set[str], bool]]]:
            node = strip(node)
            k, children = node.get("kind"), node.get("inner", [])
            if k == "CompoundStmt":
                states = [(set(held), False)]
                for child in children:
                    next_states = []
                    for locks, ended in states:
                        branch = [(locks, True)] if ended else inspect(child, set(locks))
                        if branch is None:
                            return None
                        next_states.extend(branch)
                    states = next_states
                return states
            if k == "IfStmt" and len(children) in {2, 3}:
                cond = strip(children[0])
                parts = cond.get("inner", [])
                yes, no = set(held), set(held)
                acquisition = False
                if (
                    cond.get("kind") == "BinaryOperator"
                    and cond.get("opcode") in {"==", "!="}
                    and len(parts) == 2
                ):
                    name, lock = lock_call(parts[0])
                    if (
                        name in {"pthread_mutex_lock", "pthread_mutex_trylock"}
                        and lock.startswith("&")
                        and integer(parts[1]) == 0
                    ):
                        (yes if cond["opcode"] == "==" else no).add(lock)
                        acquisition = True
                if not acquisition and inspect(cond, set(held)) is None:
                    return None
                a = inspect(children[1], yes)
                b = inspect(children[2], no) if len(children) == 3 else [(no, False)]
                return None if a is None or b is None else a + b
            if k == "DoStmt" and len(children) == 2 and integer(children[1]) == 0:
                return inspect(children[0], held)
            if k in {
                "WhileStmt",
                "ForStmt",
                "GotoStmt",
                "IndirectGotoStmt",
                "SwitchStmt",
                "CXXTryStmt",
                "CXXThrowExpr",
                "GCCAsmStmt",
                "MSAsmStmt",
                "SEHTryStmt",
            }:
                return None
            if k in {"BinaryOperator", "CompoundAssignOperator", "UnaryOperator"} and children:
                assigned = symbol(children[0])
                if any(
                    assigned == lock or assigned.startswith(lock + ".") for lock in global_locks
                ) and node.get("opcode") in {"=", "++", "--", "+=", "-="}:
                    return None
            name, lock = lock_call(node)
            if name:
                if not lock:
                    return None
                if name != "pthread_mutex_unlock":
                    # Unchecked failure cannot establish successful acquisition.
                    return None
                held.discard(lock)
                return [(held, False)]
            if (
                k == "UnaryOperator"
                and node.get("opcode") == "&"
                and symbol(children[0]) == subject
            ):
                return None
            if k == "CallExpr":
                # Callee lock effects and aliases must be independently resolved.
                return None
            if self._unsupported_lifetime_effects(node):
                return None
            # Nested calls (comma expressions, initializers, return operands)
            # may release a lock before a later access in the same statement.
            # Only standalone unlocks and the explicit acquisition branch above
            # have transfer semantics in this interpreter.
            if any(n.get("kind") == "CallExpr" for child in children for n in walk_ast(child)):
                return None
            if k == "DeclRefExpr" and symbol(node) == subject:
                access_locks.append(set(held))
            for child in children:
                if inspect(child, set(held)) is None:
                    return None
            return [(held, k == "ReturnStmt")]

        for name, fn in functions.items():
            if not any(symbol(n) == subject for n in walk_ast(fn)):
                continue
            checked.add(name)
            if inspect(self._body(fn), set()) is None:
                return False
        return bool(access_locks and set.intersection(*access_locks))


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
