"""Bounded deterministic evidence-completion for unresolved validation groups."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional


@dataclass(frozen=True)
class EvidenceCompletionRequest:
    validation_cluster_uid: str
    missing_fact: str
    reason: str


class EvidenceCompletionQueue:
    """Promote already-collected deterministic facts before asking for review.

    This deliberately does not ask an LLM to manufacture proof.  Backends may
    attach ``evidence_completion_proofs`` while gathering facts; a candidate is
    re-evaluated at most once after those facts are promoted into the stable
    deterministic-proof interface.  The queue also runs a bounded set of local
    providers.  A normal scan always closes the request as either ``completed``
    or ``exhausted``: ``requested`` is not a terminal state and must never leak
    into a completed report.
    """

    def __init__(self, *, enabled: bool = True, max_workers: int = 2) -> None:
        self.enabled = bool(enabled)
        self.max_workers = max(1, int(max_workers or 2))

    def complete(
        self,
        issue: Dict[str, Any],
        *,
        validator_data: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> Optional[EvidenceCompletionRequest]:
        if not self.enabled or str(issue.get("evidence_completion_status") or "") in {
            "completed",
            "exhausted",
            "not_applicable",
            "engine_failed",
            "interrupted",
        }:
            return None
        if not self._eligible(issue, validator_data):
            issue.setdefault("evidence_completion_status", "not_applicable")
            issue.setdefault("evidence_completion_terminal_status", "not_applicable")
            return None

        request = EvidenceCompletionRequest(
            validation_cluster_uid=str(issue.get("validation_cluster_uid") or ""),
            missing_fact=self._missing_fact(issue, validator_data),
            reason=str(validator_data.get("reasoning") or "deterministic evidence incomplete"),
        )
        proofs = list(self._completion_proofs(issue, validation_evidence))
        if proofs:
            existing = issue.get("deterministic_proofs")
            if not isinstance(existing, list):
                existing = []
                issue["deterministic_proofs"] = existing
            existing.extend(proofs)
            issue["evidence_completion_status"] = "completed"
            issue["evidence_completion_terminal_status"] = "completed_with_proof"
            issue["evidence_completion_missing_fact"] = request.missing_fact
        else:
            # This is one bounded, deterministic completion pass.  Do not
            # pretend an unimplemented asynchronous worker will finish later.
            issue["evidence_completion_status"] = "exhausted"
            issue["evidence_completion_terminal_status"] = "exhausted"
            issue["evidence_completion_missing_fact"] = request.missing_fact
        issue["evidence_completion_attempt_count"] = int(
            issue.get("evidence_completion_attempt_count") or 0
        ) + 1
        return request

    @staticmethod
    def _completion_proofs(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> Iterable[Dict[str, Any]]:
        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), Mapping) else {}
        values = (
            issue.get("evidence_completion_proofs"),
            pack.get("evidence_completion_proofs"),
        )
        for value in values:
            if isinstance(value, Mapping):
                if "proof_kind" in value or "kind" in value:
                    yield dict(value)
                else:
                    for item in value.values():
                        if isinstance(item, Mapping):
                            yield dict(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, Mapping):
                        yield dict(item)
        local_lock_proof = EvidenceCompletionQueue._local_lock_dominance_proof(
            issue,
            validation_evidence,
        )
        if local_lock_proof is not None:
            yield local_lock_proof
        guard_proof = EvidenceCompletionQueue._guard_dominance_proof(
            issue,
            validation_evidence,
        )
        if guard_proof is not None:
            yield guard_proof
        field_proof = EvidenceCompletionQueue._distinct_object_identity_proof(
            issue,
            validation_evidence,
        )
        if field_proof is not None:
            yield field_proof
        confirmation_proof = EvidenceCompletionQueue._cfg_obligation_confirmation_proof(
            issue,
            validation_evidence,
        )
        if confirmation_proof is not None:
            yield confirmation_proof

    @staticmethod
    def _function_code(
        validation_evidence: Optional[Mapping[str, Any]],
        issue: Mapping[str, Any],
    ) -> str:
        evidence = validation_evidence if isinstance(validation_evidence, Mapping) else {}
        function_context = evidence.get("function_context") if isinstance(evidence.get("function_context"), Mapping) else {}
        return str(function_context.get("code") or issue.get("issue_code") or "")

    @staticmethod
    def _code_hash(code: str, issue: Mapping[str, Any]) -> str:
        return str(
            issue.get("dependency_code_hash")
            or issue.get("code_hash")
            or hashlib.sha256(code.encode("utf-8")).hexdigest()
        )

    @staticmethod
    def _guard_dominance_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Prove an allocation result is checked on every local failure path.

        This provider only accepts an explicit null condition followed by a
        terminating return/goto before the reported dereference.  It therefore
        rejects neither merely adjacent checks nor non-terminating logging
        branches.
        """

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_allocation_result_used_without_null_check",
            "clang_cfg_alloc_result_deref_without_null_guard",
        }:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        source = str(issue.get("source") or "")
        sink = str(issue.get("sink") or "")
        if not code or not source or not sink or len(code) > 64 * 1024:
            return None
        allocation = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=", source)
        if allocation is None:
            return None
        var = allocation.group("var")
        lines = code.splitlines()
        source_index = next((i for i, line in enumerate(lines) if source.strip() in line), -1)
        sink_index = next(
            (i for i in range(source_index + 1, len(lines)) if sink.strip() in lines[i]),
            -1,
        )
        if source_index < 0 or sink_index < 0:
            return None
        null_condition = re.compile(
            rf"(?:!\s*{re.escape(var)}\b|\b{re.escape(var)}\s*==\s*(?:NULL|nullptr|0)\b|\b(?:NULL|nullptr|0)\s*==\s*{re.escape(var)}\b)"
        )
        for index in range(source_index + 1, sink_index):
            if not re.search(r"\bif\s*\(", lines[index]) or not null_condition.search(lines[index]):
                continue
            branch = lines[index]
            brace_depth = branch.count("{") - branch.count("}")
            end = index + 1
            if brace_depth > 0:
                while end < sink_index and brace_depth > 0:
                    brace_depth += lines[end].count("{") - lines[end].count("}")
                    branch += "\n" + lines[end]
                    end += 1
            if re.search(r"\b(?:return|goto)\b", branch):
                return {
                    "outcome": "reject",
                    "proof_kind": "guard_dominates_sink",
                    "producer_engine": "clang_ast_cfg_guard_dominance",
                    "fact_ids": [f"cfg:{source_index + 1}", f"cfg:{index + 1}", f"cfg:{sink_index + 1}"],
                    "cfg_nodes": [str(source_index + 1), str(index + 1), str(sink_index + 1)],
                    "subject_identity": var,
                    "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
                    "facts": ["guard_dominates_sink"],
                    "completeness": "complete",
                    "scope": f"allocation `{var}` through reported dereference",
                    "summary": f"a terminating NULL guard for `{var}` dominates the reported use",
                }
        return None

    @staticmethod
    def _distinct_object_identity_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject a same-object lifetime claim when full access paths differ."""

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_same_object_released_twice",
            "clang_cfg_use_after_release",
        }:
            return None
        source = str(issue.get("source") or "")
        sink = str(issue.get("sink") or "")
        source_path = EvidenceCompletionQueue._longest_access_path(source)
        sink_path = EvidenceCompletionQueue._longest_access_path(sink)
        if not source_path or not sink_path or source_path == sink_path:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            return None
        return {
            "outcome": "reject",
            "proof_kind": "distinct_object_identity",
            "producer_engine": "clang_ast_cfg_field_identity",
            "fact_ids": [f"object:{source_path}", f"object:{sink_path}"],
            "subject_identity": f"{source_path}!={sink_path}",
            "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
            "facts": ["distinct_object_identity"],
            "completeness": "complete",
            "scope": "source and sink access paths",
            "summary": f"`{source_path}` and `{sink_path}` are distinct object access paths",
        }

    @staticmethod
    def _longest_access_path(text: str) -> str:
        candidates = re.findall(
            r"\b[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w+|\s*\[[^\]]+\])+",
            text,
        )
        if not candidates:
            return ""
        return re.sub(r"\s+", "", max(candidates, key=len))

    @staticmethod
    def _cfg_obligation_confirmation_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a small set of complete, deterministic CFG obligations.

        These are not model classifications.  Every accepted shape requires a
        complete intraprocedural path and both ends of a semantically specific
        event pair (or a three-event state transition).  Broad heuristic rules
        such as generic leaks and unconstrained allocations intentionally do
        not appear here because their ownership/contract evidence is not yet
        complete.
        """

        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), Mapping) else {}
        ast_cfg = pack.get("ast_cfg") if isinstance(pack.get("ast_cfg"), Mapping) else {}
        path = pack.get("path") if isinstance(pack.get("path"), Mapping) else {}
        events = ast_cfg.get("events") if isinstance(ast_cfg.get("events"), list) else []
        event_kinds = {
            str(item.get("kind") or "").strip().lower()
            for item in events
            if isinstance(item, Mapping)
        }
        if not event_kinds or path.get("complete_in_function") is not True:
            return None

        # Each event set captures a complete source-to-sink safety obligation,
        # not merely a suspicious API name.  The categories are deliberately
        # generic across C/C++ projects and do not depend on project paths,
        # function names, descriptions, or model prose.
        obligation_shapes = (
            {"uninitialized_pointer_decl", "uninitialized_pointer_use"},
            {"header_length", "header_length_copy"},
            {"wide_count_read", "wide_count_sink"},
            {"length_field_load", "copy_length_use"},
            {"offset_pointer", "offset_length_copy"},
            {"unaligned_pointer_cast", "unaligned_deref"},
            {"cond_wait"},
            {"state_snapshot", "state_overwrite", "error_return_without_restore"},
            {"path_check", "path_use"},
            {"probe_status", "probe_error_condition", "success_possible_return"},
        )
        matched = next((shape for shape in obligation_shapes if shape.issubset(event_kinds)), None)
        if matched is None:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code:
            return None
        fact_ids = [
            f"cfg:{item.get('line')}:{item.get('kind')}"
            for item in events
            if isinstance(item, Mapping)
            and str(item.get("kind") or "").lower() in matched
            and item.get("line") not in (None, "")
        ]
        if len(fact_ids) < len(matched):
            return None
        return {
            "outcome": "confirm",
            "proof_kind": "deterministic_cfg_obligation_path",
            "producer_engine": "clang_ast_cfg_obligation_prover",
            "fact_ids": fact_ids,
            "cfg_nodes": [str(item.get("line")) for item in events if isinstance(item, Mapping) and str(item.get("kind") or "").lower() in matched],
            "subject_identity": str(
                issue.get("resource_identity")
                or issue.get("source_identity")
                or issue.get("resource_signature")
                or ""
            ),
            "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
            "facts": ["source_to_sink_complete", "event_path_complete", *sorted(matched)],
            "completeness": "complete",
            "scope": "complete intraprocedural AST/CFG source-to-sink path",
            "summary": "deterministic AST/CFG events establish the reported safety obligation",
        }

    @staticmethod
    def _local_lock_dominance_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Prove a false "with and without lock" claim from one local body.

        This narrow provider deliberately applies only to the AST/CFG global
        state rule.  It requires every assignment to the named object visible
        in the complete function body to be nested under the same lock, with a
        corresponding unlock, so adjacent text alone cannot suppress a race.
        """

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_global_state_written_with_and_without_lock",
            "clang_cfg_global_state_write_without_lock",
        }:
            return None
        evidence = validation_evidence if isinstance(validation_evidence, Mapping) else {}
        function_context = evidence.get("function_context") if isinstance(evidence.get("function_context"), Mapping) else {}
        code = str(function_context.get("code") or "")
        resource = str(
            issue.get("resource_signature")
            or issue.get("resource_identity")
            or ""
        ).strip()
        if not code or not resource or len(code) > 64 * 1024:
            return None

        held: list[str] = []
        assignment_locks: list[str] = []
        fact_ids: list[str] = []
        for offset, line in enumerate(code.splitlines(), start=1):
            for match in re.finditer(r"\b(?:LOCK|pthread_mutex_lock)\s*\(\s*&?([^,)]+)", line):
                held.append(match.group(1).strip())
            if resource in line and re.search(rf"\b{re.escape(resource)}\s*=", line):
                if not held:
                    return None
                assignment_locks.append(held[-1])
                fact_ids.append(f"local_cfg:{offset}")
            for match in re.finditer(r"\b(?:UNLOCK|pthread_mutex_unlock)\s*\(\s*&?([^,)]+)", line):
                lock = match.group(1).strip()
                for index in range(len(held) - 1, -1, -1):
                    if held[index] == lock:
                        held.pop(index)
                        break
        if not assignment_locks or len(set(assignment_locks)) != 1:
            return None
        lock_name = assignment_locks[0]
        if not any(lock_name in line and re.search(r"\b(?:UNLOCK|pthread_mutex_unlock)\b", line) for line in code.splitlines()):
            return None
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        return {
            "outcome": "reject",
            "proof_kind": "lock_dominates_access",
            "producer_engine": "clang_ast_cfg_local_lockset",
            "fact_ids": fact_ids,
            "code_hash": code_hash,
            "facts": ["lock_dominates_access", "all_accesses_guarded"],
            "completeness": "complete",
            "scope": f"all local assignments to {resource}",
            "summary": f"all local assignments to {resource} are nested under {lock_name}",
        }

    @staticmethod
    def _eligible(issue: Mapping[str, Any], validator_data: Mapping[str, Any]) -> bool:
        severity = str(issue.get("impact_level") or issue.get("severity") or "").lower()
        try:
            priority = int(issue.get("priority_score") or 0)
        except (TypeError, ValueError):
            priority = 0
        verdict = str(validator_data.get("verdict") or "").lower()
        return bool(
            severity in {"high", "critical"}
            or priority >= 70
            or verdict in {"verified", "rejected"}
        )

    @staticmethod
    def _missing_fact(issue: Mapping[str, Any], validator_data: Mapping[str, Any]) -> str:
        category = str(
            issue.get("defect_class") or issue.get("category") or ""
        ).lower()
        verdict = str(validator_data.get("verdict") or "").lower()
        if category in {"race", "deadlock", "unsynchronized_shared_state"}:
            return "lock_or_happens_before"
        if category in {"bounds", "integer_overflow", "buffer_overflow"}:
            return "guard_or_value_range"
        if category in {"use_after_free", "memory_leak", "resource_lifecycle"}:
            return "ownership_or_cleanup_path"
        return "cross_procedure_contract" if verdict else "decision_evidence"
