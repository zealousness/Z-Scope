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
    deterministic-proof interface.  Requests with no attached fact remain
    telemetry for later backend work.
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
            "requested",
            "not_applicable",
        }:
            return None
        if not self._eligible(issue, validator_data):
            issue.setdefault("evidence_completion_status", "not_applicable")
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
            issue["evidence_completion_missing_fact"] = request.missing_fact
        else:
            issue["evidence_completion_status"] = "requested"
            issue["evidence_completion_missing_fact"] = request.missing_fact
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
