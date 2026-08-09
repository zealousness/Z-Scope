"""Bounded deterministic evidence-completion for unresolved validation groups."""

from __future__ import annotations

import hashlib
import json
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

    def __init__(
        self,
        *,
        enabled: bool = True,
        max_workers: int = 2,
        enable_v11_providers: bool = True,
    ) -> None:
        self.enabled = bool(enabled)
        self.max_workers = max(1, int(max_workers or 2))
        # v1.1 providers are independently switchable while their transition
        # audit is running.  Existing v3 providers remain available so a
        # disabled rollout cannot change prior evidence semantics.
        self.enable_v11_providers = bool(enable_v11_providers)

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
        # A Validator may identify a concrete counter-fact that conflicts with
        # an otherwise local rejection proof.  Keep that conflict visible for
        # review instead of allowing the post-validation completion pass to
        # erase it.  This is intentionally scoped to rejection: a complete
        # positive proof is still evidence of a real obligation.
        if issue.get("blocking_negative_evidence") is True:
            proofs = [
                proof for proof in proofs
                if str(proof.get("outcome") or "").lower() != "reject"
            ]
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

    def complete_prevalidation(
        self,
        issue: Dict[str, Any],
        *,
        validation_evidence: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Promote already available deterministic facts before an LLM call.

        This is intentionally not a second validation path: it runs the same
        bounded providers used after a Validator response, but does not mark an
        unresolved candidate exhausted.  That lets a later Validator name one
        missing fact while ensuring complete local proof never pays for an LLM
        invocation.
        """

        if not self.enabled:
            return False
        existing = issue.get("deterministic_proofs")
        proofs = list(self._completion_proofs(issue, validation_evidence))
        # A Validator may identify a concrete counter-fact that conflicts with
        # an otherwise local rejection proof.  Keep that conflict visible for
        # review instead of allowing the post-validation completion pass to
        # erase it.  This is intentionally scoped to rejection: a complete
        # positive proof is still evidence of a real obligation.
        if issue.get("blocking_negative_evidence") is True:
            proofs = [
                proof for proof in proofs
                if str(proof.get("outcome") or "").lower() != "reject"
            ]
        if not proofs:
            issue.setdefault("prevalidation_fact_completion", "not_applicable")
            return False
        if not isinstance(existing, list):
            existing = []
            issue["deterministic_proofs"] = existing
        known = {
            (str(item.get("outcome") or ""), str(item.get("proof_kind") or ""))
            for item in existing
            if isinstance(item, Mapping)
        }
        for proof in proofs:
            key = (str(proof.get("outcome") or ""), str(proof.get("proof_kind") or ""))
            if key not in known:
                existing.append(proof)
                known.add(key)
        issue["prevalidation_fact_completion"] = "completed_with_proof"
        issue["evidence_completion_status"] = "completed"
        issue["evidence_completion_terminal_status"] = "completed_with_proof"
        issue["evidence_completion_attempt_count"] = int(
            issue.get("evidence_completion_attempt_count") or 0
        ) + 1
        return True

    def _completion_proofs(
        self,
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
        ast_guard_proof = EvidenceCompletionQueue._ast_guard_dominance_proof(issue)
        if ast_guard_proof is not None:
            yield ast_guard_proof
        fd_transfer_proof = EvidenceCompletionQueue._fd_transfer_or_failure_proof(issue)
        if fd_transfer_proof is not None:
            yield fd_transfer_proof
        allocation_proof = EvidenceCompletionQueue._allocation_context_proof(issue)
        if allocation_proof is not None:
            yield allocation_proof
        array_proof = EvidenceCompletionQueue._array_shape_rejection_proof(issue)
        if array_proof is not None:
            yield array_proof
        transfer_proof = EvidenceCompletionQueue._resource_transfer_proof(issue)
        if transfer_proof is not None:
            yield transfer_proof
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
        graph_confirmation_proof = EvidenceCompletionQueue._graph_contract_confirmation_proof(issue)
        if graph_confirmation_proof is not None:
            yield graph_confirmation_proof
        if self.enable_v11_providers:
            lock_protocol_proof = EvidenceCompletionQueue._balanced_lock_protocol_proof(
                issue,
                validation_evidence,
            )
            if lock_protocol_proof is not None:
                yield lock_protocol_proof
            allocation_copy_proof = EvidenceCompletionQueue._allocation_copy_capacity_proof(
                issue,
                validation_evidence,
            )
            if allocation_copy_proof is not None:
                yield allocation_copy_proof
            failed_member_proof = EvidenceCompletionQueue._failed_member_acquisition_cleanup_proof(
                issue,
                validation_evidence,
            )
            if failed_member_proof is not None:
                yield failed_member_proof
            pointer_provenance_proof = EvidenceCompletionQueue._pointer_offset_provenance_proof(
                issue,
                validation_evidence,
            )
            if pointer_provenance_proof is not None:
                yield pointer_provenance_proof
            async_stack_proof = EvidenceCompletionQueue._async_stack_escape_proof(
                issue,
                validation_evidence,
            )
            if async_stack_proof is not None:
                yield async_stack_proof
            unlink_proof = EvidenceCompletionQueue._container_unlink_without_release_proof(
                issue,
                validation_evidence,
            )
            if unlink_proof is not None:
                yield unlink_proof
            failure_lock_proof = EvidenceCompletionQueue._lock_held_on_failure_return_proof(
                issue,
                validation_evidence,
            )
            if failure_lock_proof is not None:
                yield failure_lock_proof
            incomplete_cleanup_proof = EvidenceCompletionQueue._incomplete_owner_cleanup_proof(
                issue,
                validation_evidence,
            )
            if incomplete_cleanup_proof is not None:
                yield incomplete_cleanup_proof
            lifecycle_protocol_proof = EvidenceCompletionQueue._lifecycle_protocol_confirmation_proof(
                issue,
                validation_evidence,
            )
            if lifecycle_protocol_proof is not None:
                yield lifecycle_protocol_proof

    @staticmethod
    def _lifecycle_protocol_confirmation_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm explicit borrow/owner/concurrency protocol violations.

        These patterns used to reach a Validator with an accurate structured
        event but no proof because the earlier provider covered only generic
        source-to-sink pairs.  Each branch below requires the detector's
        field-sensitive event and a complete local path; it never treats a
        rule name or a model explanation as proof on its own.
        """

        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        rule = str(issue.get("rule") or "").lower()
        by_kind: Dict[str, list[Mapping[str, Any]]] = {}
        for event in events:
            kind = str(event.get("kind") or "").lower()
            if kind:
                by_kind.setdefault(kind, []).append(event)
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)

        def proof(
            kind: str,
            selected: Iterable[Mapping[str, Any]],
            facts: list[str],
            summary: str,
            subject: str = "",
        ) -> Dict[str, Any]:
            return EvidenceCompletionQueue._proof_from_ast(
                issue,
                outcome="confirm",
                proof_kind=kind,
                producer_engine="clang_ast_cfg_protocol_v11",
                events=selected,
                facts=facts,
                summary=summary,
                scope="complete intraprocedural ownership/concurrency protocol path",
                subject_identity=subject,
            )

        if rule == "clang_cfg_parent_release_without_owned_member_cleanup":
            leaks = by_kind.get("owned_member_leak", [])
            if len(leaks) == 1:
                member = EvidenceCompletionQueue._normalize_symbol(
                    leaks[0].get("variable")
                ).replace("->", ".")
                owner = member.rsplit(".", 1)[0] if "." in member else ""
                if owner and re.search(
                    rf"\b(?:safe_free|free|release|destroy)\s*\(\s*{re.escape(owner)}\s*\)",
                    code,
                    re.IGNORECASE,
                ) and not re.search(
                    rf"\b(?:safe_free|free|release|destroy)\s*\(\s*{re.escape(member.replace('.', '->'))}\s*\)",
                    code,
                    re.IGNORECASE,
                ) and re.search(
                    rf"\b{re.escape(member.replace('.', '->'))}\s*=\s*"
                    r"(?:[A-Za-z_]\w*\s*\()?[^;]*(?:alloc|dup|open|create)[A-Za-z_0-9]*\s*\(",
                    code,
                    re.IGNORECASE,
                ):
                    return proof(
                        "owned_member_left_live_when_parent_released",
                        [leaks[0]],
                        ["field_sensitive_owned_member", "parent_release", "member_not_released"],
                        "a field identified as owned remains live when its parent is released",
                        member,
                    )

        return None

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
    def _evidence_code_hash(issue: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
        """Return a stable hash for structured code facts when source text is absent.

        The AST/CFG collector records source-derived statement facts even when
        a function body is intentionally omitted from the LLM validation
        context.  Hashing their canonical representation keeps a proof tied to
        the exact code snapshot instead of falling back to a hash of an empty
        string.
        """

        explicit = str(issue.get("dependency_code_hash") or issue.get("code_hash") or "")
        if explicit:
            return explicit
        encoded = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _ast_pack(issue: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any], list[Mapping[str, Any]]]:
        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), Mapping) else {}
        ast_cfg = pack.get("ast_cfg") if isinstance(pack.get("ast_cfg"), Mapping) else {}
        path = pack.get("path") if isinstance(pack.get("path"), Mapping) else {}
        events = [item for item in ast_cfg.get("events", []) if isinstance(item, Mapping)]
        return ast_cfg, path, events

    @staticmethod
    def _normalize_symbol(value: Any) -> str:
        return re.sub(r"\s+", "", str(value or "").lstrip("*&"))

    @staticmethod
    def _proof_from_ast(
        issue: Mapping[str, Any],
        *,
        outcome: str,
        proof_kind: str,
        producer_engine: str,
        events: Iterable[Mapping[str, Any]],
        facts: Iterable[str],
        summary: str,
        scope: str,
        subject_identity: str = "",
    ) -> Dict[str, Any]:
        selected = list(events)
        fact_ids = [
            f"ast_cfg:{item.get('line')}:{item.get('kind')}"
            for item in selected
            if item.get("line") not in (None, "") and item.get("kind")
        ]
        ast_cfg, _path, _events = EvidenceCompletionQueue._ast_pack(issue)
        return {
            "outcome": outcome,
            "proof_kind": proof_kind,
            "producer_engine": producer_engine,
            "proof_version": "zscope.decision-proof.v3",
            "fact_ids": fact_ids,
            "cfg_nodes": [str(item.get("line")) for item in selected if item.get("line") not in (None, "")],
            "subject_identity": subject_identity,
            "code_hash": EvidenceCompletionQueue._evidence_code_hash(issue, ast_cfg),
            "facts": list(facts),
            "completeness": "complete",
            "scope": scope,
            "summary": summary,
        }

    @staticmethod
    def _proof_from_code(
        issue: Mapping[str, Any],
        *,
        outcome: str,
        proof_kind: str,
        producer_engine: str,
        code: str,
        line_numbers: Iterable[int],
        facts: Iterable[str],
        summary: str,
        scope: str,
        subject_identity: str = "",
    ) -> Dict[str, Any]:
        lines = sorted({int(line) for line in line_numbers if int(line) > 0})
        return {
            "outcome": outcome,
            "proof_kind": proof_kind,
            "producer_engine": producer_engine,
            "proof_version": "zscope.decision-proof.v3",
            "fact_ids": [f"source_cfg:{line}" for line in lines],
            "cfg_nodes": [str(line) for line in lines],
            "subject_identity": subject_identity,
            "code_hash": EvidenceCompletionQueue._code_hash(code, issue),
            "facts": list(facts),
            "completeness": "complete",
            "scope": scope,
            "summary": summary,
        }

    @staticmethod
    def _code_lines(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> list[str]:
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        if not code or len(code) > 64 * 1024:
            return []
        return code.splitlines()

    @staticmethod
    def _lock_argument(text: str, *, acquire: bool) -> str:
        names = (
            r"(?:LOCK|pthread_mutex_lock|pthread_rwlock_[rw]dlock)"
            if acquire
            else r"(?:UNLOCK|pthread_mutex_unlock|pthread_rwlock_unlock)"
        )
        match = re.search(rf"\b{names}\s*\(\s*&?([^,)]+)", text)
        return EvidenceCompletionQueue._normalize_symbol(match.group(1)) if match else ""

    @staticmethod
    def _balanced_lock_protocol_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject simple lock-protocol false positives from complete source CFG.

        The provider deliberately handles only lexical lock/unlock pairs with
        no ``goto``/``switch``/``else`` ambiguity between the matching pair.
        More complicated interprocedural or branch-dependent protocols remain
        reviewable until the project fact pass supplies a formal contract.
        """

        rule = str(issue.get("rule") or "").lower()
        if rule not in {
            "clang_cfg_return_with_lock_held",
            "clang_cfg_unlock_without_matching_lock",
        }:
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        if re.search(r"\b(?:goto|switch|case)\b", code):
            return None

        if rule == "clang_cfg_unlock_without_matching_lock":
            for index, text in enumerate(lines):
                lock = EvidenceCompletionQueue._lock_argument(text, acquire=False)
                if not lock:
                    continue
                # A matching lexical acquire must appear after the previous
                # return and before the reported unlock, without an ``else``
                # branch that could bypass it.
                previous_return = next(
                    (
                        prior + 1
                        for prior in range(index - 1, -1, -1)
                        if re.search(r"\breturn\b", lines[prior])
                    ),
                    0,
                )
                segment = lines[previous_return:index]
                if any(re.search(r"\belse\b", item) for item in segment):
                    continue
                acquire_index = next(
                    (
                        prior
                        for prior in range(index - 1, -1, -1)
                        if EvidenceCompletionQueue._lock_argument(lines[prior], acquire=True) == lock
                    ),
                    -1,
                )
                if acquire_index < 0:
                    continue
                if any("return" in item for item in lines[acquire_index + 1:index]):
                    continue
                return EvidenceCompletionQueue._proof_from_code(
                    issue,
                    outcome="reject",
                    proof_kind="matching_lock_dominates_unlock",
                    producer_engine="clang_ast_cfg_lock_protocol",
                    code=code,
                    line_numbers=[acquire_index + 1, index + 1],
                    facts=["matching_lock_dominates_unlock"],
                    summary="a matching local lock acquisition precedes the reported unlock on the same complete path",
                    scope="complete lexical lock protocol segment",
                    subject_identity=lock,
                )
            return None

        # For a return-with-lock-held candidate, inspect every return in a
        # branch-free local body.  Each acquire must have a matching release
        # before its subsequent return.  This intentionally refuses to prove
        # safety in a body containing ``else`` because a linear scan is then
        # insufficient to establish all paths.
        if re.search(r"\belse\b", code):
            return None
        held: list[tuple[str, int]] = []
        return_lines: list[int] = []
        for index, text in enumerate(lines):
            acquired = EvidenceCompletionQueue._lock_argument(text, acquire=True)
            if acquired:
                held.append((acquired, index + 1))
            released = EvidenceCompletionQueue._lock_argument(text, acquire=False)
            if released:
                match_index = next(
                    (item for item in range(len(held) - 1, -1, -1) if held[item][0] == released),
                    -1,
                )
                if match_index >= 0:
                    held.pop(match_index)
            if re.search(r"\breturn\b", text):
                return_lines.append(index + 1)
                if held:
                    return None
        if return_lines:
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="balanced_lock_return_paths",
                producer_engine="clang_ast_cfg_lock_protocol",
                code=code,
                line_numbers=return_lines,
                facts=["all_return_paths_unlocked"],
                summary="every reachable return in the complete local lock protocol is preceded by matching unlocks",
                scope="complete branch-free local lock protocol",
            )
        return None

    @staticmethod
    def _allocation_copy_capacity_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject a copy-overflow claim when a complete capacity relation is explicit."""

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_narrowed_allocation_original_length_copy",
            "clang_cfg_heap_copy_length_mismatch",
        }:
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        allocations: dict[str, tuple[str, int]] = {}
        for index, text in enumerate(lines, start=1):
            match = re.search(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^;=]+\)\s*)?"
                r"(?:[A-Za-z_]\w*(?:alloc|malloc|calloc)[A-Za-z_0-9]*)\s*\(\s*(?P<size>[^,)]+)",
                text,
                re.IGNORECASE,
            )
            if match:
                allocations[match.group("var")] = (match.group("size").replace(" ", ""), index)
        for index, text in enumerate(lines, start=1):
            call = re.search(r"\b(?:memcpy|memmove)\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,[^,]+,\s*(?P<len>[^)]+)\)", text)
            if not call or call.group("dst") not in allocations:
                continue
            size, allocation_line = allocations[call.group("dst")]
            length = call.group("len").replace(" ", "")
            plus_one = re.fullmatch(r"\(?([A-Za-z_]\w*)\+1\)?", size)
            if plus_one is None or plus_one.group(1) != length:
                continue
            # A terminating overflow guard is the explicit source-derived
            # witness that makes ``n + 1`` a complete capacity proof.
            symbol = plus_one.group(1)
            guard = next(
                (
                    guard_line
                    for guard_line, item in enumerate(lines[: allocation_line - 1], start=1)
                    if re.search(
                        rf"\b{re.escape(symbol)}\b\s*>=\s*(?:SIZE_MAX|UINT(?:32|64)_MAX|[A-Z][A-Z0-9_]*)",
                        item,
                    )
                    and re.search(r"\breturn\b", "\n".join(lines[guard_line - 1:guard_line + 3]))
                ),
                0,
            )
            if not guard:
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="allocation_capacity_dominates_copy",
                producer_engine="clang_ast_cfg_capacity_relation",
                code=code,
                line_numbers=[guard, allocation_line, index],
                facts=["allocation_capacity_exceeds_copy", "same_length_symbol"],
                summary="a guarded allocation of n + 1 bytes dominates a copy of n bytes",
                scope="complete allocation-to-copy capacity relation",
                subject_identity=call.group("dst"),
            )
        return None

    @staticmethod
    def _failed_member_acquisition_cleanup_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Reject parent-member leak reports on an allocation-failure-only branch."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_parent_release_without_owned_member_cleanup":
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        source = str(issue.get("source") or "")
        member_match = re.search(r"\b([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)", source)
        parent_match = re.search(r"SAFE_FREE\s*\(\s*([A-Za-z_]\w*)\s*\)", str(issue.get("sink") or ""))
        if not member_match or not parent_match or member_match.group(1) != parent_match.group(1):
            return None
        parent, member = member_match.groups()
        pattern = re.compile(
            rf"if\s*\(\s*!\s*{re.escape(parent)}\s*->\s*{re.escape(member)}\s*\)"
        )
        for index, text in enumerate(lines, start=1):
            if not pattern.search(text):
                continue
            window = "\n".join(lines[index - 1:index + 5])
            if not re.search(rf"SAFE_FREE\s*\(\s*{re.escape(parent)}\s*\)", window):
                continue
            if not re.search(r"\breturn\b", window):
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="failed_member_acquisition_cleanup",
                producer_engine="clang_ast_cfg_ownership",
                code=code,
                line_numbers=[index],
                facts=["member_acquisition_failed", "parent_cleanup_on_failure_only"],
                summary="the parent is released only on the branch where its owned member acquisition failed",
                scope="complete member-acquisition failure branch",
                subject_identity=f"{parent}->{member}",
            )
        return None

    @staticmethod
    def _pointer_offset_provenance_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Distinguish pointer-relative buffer access from integer-to-pointer use."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_wire_integer_cast_to_pointer_deref":
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        pointer_params = {
            item
            for item in re.findall(r"\b[A-Za-z_]\w*\s*\*\s*([A-Za-z_]\w*)", code.split("{")[0])
        }
        for index, text in enumerate(lines, start=1):
            match = re.search(
                r"\([^)]*\*[^)]*\)\s*\(\s*([A-Za-z_]\w*)\s*\+\s*[^)]+\)",
                text,
            )
            if not match or match.group(1) not in pointer_params:
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="reject",
                proof_kind="pointer_offset_not_data_pointer",
                producer_engine="clang_ast_cfg_pointer_provenance",
                code=code,
                line_numbers=[index],
                facts=["pointer_derived_from_pointer_base", "not_data_integer_cast"],
                summary="the reported cast is derived from a pointer parameter plus an offset, not from serialized integer data",
                scope="complete local pointer provenance",
                subject_identity=match.group(1),
            )
        return None

    @staticmethod
    def _async_stack_escape_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a local stack address escaping through an asynchronous worker."""

        category = str(issue.get("defect_class") or issue.get("category") or "").lower()
        rule = str(issue.get("rule") or "").lower()
        if category != "stack_escape" and rule != "clang_cfg_stack_address_passed_to_thread":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        stack_events = [item for item in events if str(item.get("kind") or "").lower() == "stack_object"]
        escape_events = [item for item in events if str(item.get("kind") or "").lower() == "thread_arg_escape"]
        if not stack_events or not escape_events:
            return None
        stack = stack_events[0]
        escaped = next(
            (
                item for item in escape_events
                if EvidenceCompletionQueue._normalize_symbol(item.get("variable"))
                == EvidenceCompletionQueue._normalize_symbol(stack.get("variable"))
            ),
            None,
        )
        if escaped is None:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        escape_line = int(escaped.get("line") or 0)
        # The asynchronous lifetime proof is deliberately strict: detached
        # worker creation is enough, while a join before every return negates
        # the escape.  A non-detached thread without a join remains reviewable.
        detached = bool(re.search(r"\bpthread_detach\s*\(", code))
        joined_after_escape = any(
            re.search(r"\bpthread_join\s*\(", text)
            for text in lines[max(escape_line, 0):]
        )
        if not detached or joined_after_escape:
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="confirm",
            proof_kind="async_stack_address_escape",
            producer_engine="clang_ast_cfg_async_lifetime",
            events=[stack, escaped],
            facts=["stack_object_address_escapes", "async_lifetime_unbounded"],
            summary="a local stack object is passed to a detached worker without a completing join",
            scope="complete local asynchronous thread handoff",
            subject_identity=EvidenceCompletionQueue._normalize_symbol(stack.get("variable")),
        )

    @staticmethod
    def _container_unlink_without_release_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm an unlinked container owner that has no release or transfer path."""

        rule = str(issue.get("rule") or "").lower()
        if rule not in {
            "container_unlink_without_release",
            "clang_cfg_container_unlink_without_release",
        }:
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        unlink_events = [
            item for item in events
            if str(item.get("kind") or "").lower()
            in {"container_unlink", "container_detach", "ownership_unlink"}
        ]
        if not unlink_events:
            lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
            if not lines:
                return None
            for index, text in enumerate(lines, start=1):
                if re.search(r"\*\s*[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*->\s*next", text):
                    unlink_events = [{"kind": "container_unlink", "line": index, "expression": text}]
                    break
        if not unlink_events:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        unlink_line = int(unlink_events[0].get("line") or 0)
        remainder = "\n".join(lines[unlink_line:])
        subject = EvidenceCompletionQueue._normalize_symbol(
            unlink_events[0].get("variable") or issue.get("resource_identity")
        )
        if not subject:
            assign = re.search(r"\*\s*[A-Za-z_]\w*\s*=\s*([A-Za-z_]\w*)\s*->\s*next", str(unlink_events[0].get("expression") or ""))
            subject = assign.group(1) if assign else ""
        if not subject:
            return None
        if re.search(rf"\b(?:SAFE_FREE|free|release|destroy)\s*\(\s*{re.escape(subject)}\b", remainder, re.IGNORECASE):
            return None
        if re.search(rf"\b(?:return|\*)\s*{re.escape(subject)}\b", remainder):
            return None
        return EvidenceCompletionQueue._proof_from_code(
            issue,
            outcome="confirm",
            proof_kind="container_unlink_without_release",
            producer_engine="clang_ast_cfg_container_ownership",
            code=code,
            line_numbers=[unlink_line],
            facts=["container_owner_unlinked", "ownership_not_transferred_or_released"],
            summary="the container ownership link is removed and no release or transfer of the detached object follows",
            scope="complete local container-detach path",
            subject_identity=subject,
        )

    @staticmethod
    def _lock_held_on_failure_return_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a failure branch that returns while a local lock remains held."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_return_with_lock_held":
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        held: list[tuple[str, int]] = []
        for index, text in enumerate(lines, start=1):
            acquired = EvidenceCompletionQueue._lock_argument(text, acquire=True)
            if acquired:
                held.append((acquired, index))
            released = EvidenceCompletionQueue._lock_argument(text, acquire=False)
            if released:
                match_index = next(
                    (item for item in range(len(held) - 1, -1, -1) if held[item][0] == released),
                    -1,
                )
                if match_index >= 0:
                    held.pop(match_index)
            if not (held and re.search(r"\breturn\s*-?(?:1|[A-Za-z_]\w*)\s*;", text)):
                continue
            # A return inside a failure branch is a complete witness only if a
            # preceding condition names the failed acquisition or NULL guard.
            preceding = "\n".join(lines[max(0, index - 5):index])
            if not re.search(r"\bif\s*\([^)]*(?:!|==\s*NULL|<\s*0)", preceding):
                continue
            lock, lock_line = held[-1]
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="confirm",
                proof_kind="lock_held_on_failure_return",
                producer_engine="clang_ast_cfg_lock_protocol",
                code=code,
                line_numbers=[lock_line, index],
                facts=["lock_acquired_before_failure", "failure_returns_with_lock_held"],
                summary="a failure branch returns after a matching local lock acquisition without an intervening unlock",
                scope="complete local failure-return lock path",
                subject_identity=lock,
            )
        return None

    @staticmethod
    def _incomplete_owner_cleanup_proof(
        issue: Mapping[str, Any],
        validation_evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Confirm a field-sensitive cleanup that omits initialized owner members."""

        category = str(issue.get("defect_class") or issue.get("category") or "").lower()
        rule = str(issue.get("rule") or "").lower()
        if category not in {"incomplete_cleanup", "memory_leak"} and "member_cleanup" not in rule:
            return None
        _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        lines = EvidenceCompletionQueue._code_lines(issue, validation_evidence)
        if not lines:
            return None
        code = "\n".join(lines)
        initialized: dict[str, set[str]] = {}
        released: dict[str, set[str]] = {}
        for index, text in enumerate(lines, start=1):
            assignment = re.search(
                r"\b(?P<owner>[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w+)*?)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*"
                r"(?P<api>[A-Za-z_]\w*)\s*\(",
                text,
                re.IGNORECASE,
            )
            if assignment and re.search(r"(?:alloc|dup|open|create)", assignment.group("api"), re.IGNORECASE):
                owner = EvidenceCompletionQueue._normalize_symbol(assignment.group("owner"))
                initialized.setdefault(owner, set()).add(assignment.group("field"))
            cleanup = re.search(
                r"\b(?:SAFE_FREE|free|close|release)\s*\(\s*(?P<owner>[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w+)*?)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)",
                text,
                re.IGNORECASE,
            )
            if cleanup:
                owner = EvidenceCompletionQueue._normalize_symbol(cleanup.group("owner"))
                released.setdefault(owner, set()).add(cleanup.group("field"))
        for owner, fields in initialized.items():
            missing = fields - released.get(owner, set())
            if len(fields) < 2 or not missing:
                continue
            owner_release_line = next(
                (
                    index
                    for index, text in enumerate(lines, start=1)
                    if re.search(
                        rf"\b(?:SAFE_FREE|free|close|release|reset|destroy)\s*\(\s*"
                        rf"(?:{re.escape(owner.replace('.', '->'))}|{re.escape(owner)})"
                        rf"(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?",
                        text,
                        re.IGNORECASE,
                    )
                ),
                0,
            )
            if not owner_release_line:
                continue
            return EvidenceCompletionQueue._proof_from_code(
                issue,
                outcome="confirm",
                proof_kind="incomplete_owner_cleanup",
                producer_engine="clang_ast_cfg_ownership",
                code=code,
                line_numbers=[owner_release_line],
                facts=["multiple_owned_members_initialized", "owned_member_not_released"],
                summary="a cleanup/reset path releases an owner while initialized owned members remain uncleaned",
                scope="complete field-sensitive owner cleanup path",
                subject_identity=owner,
            )
        return None

    @staticmethod
    def _ast_guard_dominance_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject a null-dereference candidate using AST guard and CFG facts.

        This is deliberately stricter than a textual nearby-check heuristic:
        the acquisition, guard, terminating return and reported dereference
        must belong to one complete intraprocedural path, and all reference the
        same normalized value.
        """

        if str(issue.get("rule") or "").lower() not in {
            "clang_cfg_allocation_result_used_without_null_check",
            "clang_cfg_alloc_result_deref_without_null_guard",
        }:
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        acquires = [item for item in events if str(item.get("kind") or "").lower() in {"acquire", "allocation_result"}]
        uses = [
            item
            for item in events
            if str(item.get("kind") or "").lower()
            in {"deref", "unchecked_allocation_use"}
        ]
        guards = ast_cfg.get("condition_guards") if isinstance(ast_cfg.get("condition_guards"), list) else []
        returns = ast_cfg.get("scope_summary", {}).get("return_lines", []) if isinstance(ast_cfg.get("scope_summary"), Mapping) else []
        if not isinstance(returns, list):
            return None
        for acquire in acquires:
            symbol = EvidenceCompletionQueue._normalize_symbol(acquire.get("variable"))
            acquire_line = int(acquire.get("line") or 0)
            if not symbol or acquire_line <= 0:
                continue
            for use in uses:
                use_line = int(use.get("line") or 0)
                if EvidenceCompletionQueue._normalize_symbol(use.get("variable")) != symbol or use_line < acquire_line:
                    continue
                for guard in guards:
                    if not isinstance(guard, Mapping):
                        continue
                    guard_line = int(guard.get("line") or 0)
                    condition = str(guard.get("condition") or "")
                    null_check = re.compile(
                        rf"(?:!\s*\*?\s*{re.escape(symbol)}\b|\*?\s*{re.escape(symbol)}\s*==\s*(?:NULL|nullptr|0)\b|(?:NULL|nullptr|0)\s*==\s*\*?\s*{re.escape(symbol)}\b)"
                    )
                    if not (acquire_line < guard_line <= use_line and null_check.search(condition)):
                        continue
                    # A return immediately after (or in the same tiny branch
                    # as) the guard is the conservative local termination
                    # witness available in the fact model.
                    if not any(guard_line < int(line) <= guard_line + 3 for line in returns if isinstance(line, int)):
                        continue
                    return EvidenceCompletionQueue._proof_from_ast(
                        issue,
                        outcome="reject",
                        proof_kind="guard_dominates_sink",
                        producer_engine="clang_ast_cfg_guard_dominance",
                        events=[acquire, {"kind": "null_guard", "line": guard_line}, use],
                        facts=[
                            "same_symbol",
                            "terminating_null_guard",
                            "guard_dominates_reported_use",
                            "guard_dominates_sink",
                        ],
                        summary="a terminating null guard dominates the reported allocation use",
                        scope="complete intraprocedural allocation-to-use path",
                        subject_identity=symbol,
                    )
        return None

    @staticmethod
    def _fd_transfer_or_failure_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject FD-leak candidates proven to be failed acquisition or transfer.

        A descriptor is not leaked on the branch where acquisition explicitly
        failed.  Likewise, returning the descriptor transfers ownership to the
        caller.  Global storage is treated as a durable ownership transfer only
        for the conventional, explicit ``g_`` global form; arbitrary member
        writes remain reviewable because their lifetime is not proven here.
        """

        if str(issue.get("rule") or "").lower() != "clang_cfg_fd_open_return_without_close":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path and path.get("complete_in_function") is not True:
            return None
        opens = [item for item in events if str(item.get("kind") or "").lower() == "fd_open"]
        exits = [item for item in events if str(item.get("kind") or "").lower() == "return_without_fd_close"]
        guards = ast_cfg.get("condition_guards") if isinstance(ast_cfg.get("condition_guards"), list) else []
        for opened in opens:
            fd = EvidenceCompletionQueue._normalize_symbol(opened.get("variable"))
            open_line = int(opened.get("line") or 0)
            expression = str(opened.get("expression") or "")
            if not fd or open_line <= 0:
                continue
            lhs = expression.split("=", 1)[0].strip() if "=" in expression else ""
            if re.match(r"^g_[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+$", lhs):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="durable_global_owner_transfer",
                    producer_engine="clang_ast_cfg_fd_ownership",
                    events=[opened],
                    facts=["fd_stored_in_global_owner", "ownership_transfer_complete"],
                    summary="the descriptor is assigned to an explicit global owner",
                    scope="descriptor ownership transfer",
                    subject_identity=lhs,
                )
            for exited in exits:
                exit_line = int(exited.get("line") or 0)
                return_expression = str(exited.get("expression") or "")
                if exit_line <= open_line:
                    continue
                if re.search(rf"\breturn\s+{re.escape(fd)}\s*;", return_expression):
                    return EvidenceCompletionQueue._proof_from_ast(
                        issue,
                        outcome="reject",
                        proof_kind="return_value_ownership_transfer",
                        producer_engine="clang_ast_cfg_fd_ownership",
                        events=[opened, exited],
                        facts=["descriptor_returned_to_caller", "ownership_transfer_complete"],
                        summary="the descriptor is returned to the caller as the ownership result",
                        scope="descriptor ownership transfer",
                        subject_identity=fd,
                    )
                if not re.search(r"\breturn\s*-1\s*;", return_expression):
                    continue
                for guard in guards:
                    if not isinstance(guard, Mapping):
                        continue
                    guard_line = int(guard.get("line") or 0)
                    condition = str(guard.get("condition") or "")
                    failed_fd = re.compile(
                        rf"\b{re.escape(fd)}\s*(?:<|<=)\s*(?:0|-1)\b|\b{re.escape(fd)}\s*==\s*-1\b"
                    )
                    if open_line < guard_line < exit_line and exit_line - guard_line <= 3 and failed_fd.search(condition):
                        return EvidenceCompletionQueue._proof_from_ast(
                            issue,
                            outcome="reject",
                            proof_kind="failed_acquisition_exit",
                            producer_engine="clang_ast_cfg_fd_ownership",
                            events=[opened, {"kind": "fd_failure_guard", "line": guard_line}, exited],
                            facts=["fd_failure_guard", "failure_return"],
                            summary="the reported return is guarded by a failed descriptor acquisition",
                            scope="failed descriptor acquisition branch",
                            subject_identity=fd,
                        )
        return None

    @staticmethod
    def _allocation_context_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject allocation-limit leads when a complete local fact disproves them.

        The provider does not guess that a caller has a limit.  It accepts only
        an explicit terminating upper-bound guard in the same function.  An
        allocation-wrapper body without a caller fact remains a triage signal,
        not a rejection proof: missing caller evidence cannot prove that no
        reachable caller controls the allocation size.
        """

        if str(issue.get("rule") or "").lower() != "clang_cfg_external_size_allocation_without_limit":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        allocations = [item for item in events if str(item.get("kind") or "").lower() == "unbounded_allocation"]
        guards = ast_cfg.get("condition_guards") if isinstance(ast_cfg.get("condition_guards"), list) else []
        summary = ast_cfg.get("scope_summary") if isinstance(ast_cfg.get("scope_summary"), Mapping) else {}
        returns = summary.get("return_lines") if isinstance(summary.get("return_lines"), list) else []
        for allocation in allocations:
            expression = str(allocation.get("expression") or "")
            line = int(allocation.get("line") or 0)
            terms = {
                token
                for token in re.findall(r"\b[A-Za-z_]\w*\b", str(allocation.get("variable") or ""))
                if token.lower() not in {"size", "sizeof", "void", "char", "int", "long", "short"}
            }
            if not terms or line <= 0:
                continue
            for guard in guards:
                if not isinstance(guard, Mapping):
                    continue
                guard_line = int(guard.get("line") or 0)
                condition = str(guard.get("condition") or "")
                bounded = any(
                    re.search(rf"\b{re.escape(term)}\s*>\s*(?:[A-Z][A-Z0-9_]*|\d+)\b", condition)
                    for term in terms
                )
                if not (bounded and guard_line < line and any(guard_line < int(ret) <= guard_line + 3 for ret in returns if isinstance(ret, int))):
                    continue
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="terminating_allocation_upper_bound",
                    producer_engine="clang_ast_cfg_allocation_context",
                    events=[allocation, {"kind": "upper_bound_guard", "line": guard_line}],
                    facts=["explicit_upper_bound", "terminating_guard", "guard_dominates_allocation"],
                    summary="a terminating upper-bound guard dominates the allocation",
                    scope="complete intraprocedural allocation path",
                )
        return None

    @staticmethod
    def _array_shape_rejection_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject fixed-array leads contradicted by the structured array facts."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_unbounded_count_indexes_fixed_array":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        by_kind = {str(item.get("kind") or "").lower(): item for item in events}
        fixed = by_kind.get("fixed_array")
        loop = by_kind.get("count_loop")
        write = by_kind.get("array_write")
        if not (fixed and loop and write):
            return None
        fixed_var = EvidenceCompletionQueue._normalize_symbol(fixed.get("variable"))
        write_var = EvidenceCompletionQueue._normalize_symbol(write.get("variable"))
        write_expression = str(write.get("expression") or "")
        if fixed_var and write_var and (
            fixed_var != write_var
            or (
                bool(write_expression)
                and not re.search(rf"\b{re.escape(fixed_var)}\s*\[", write_expression)
            )
        ):
            return EvidenceCompletionQueue._proof_from_ast(
                issue,
                outcome="reject",
                proof_kind="array_sink_identity_mismatch",
                producer_engine="clang_ast_cfg_bounds",
                events=[fixed, write],
                facts=["fixed_array_identity", "write_identity_mismatch"],
                summary="the reported write targets a different object than the modeled fixed array",
                scope="complete intraprocedural array access path",
                subject_identity=f"{fixed_var}!={write_var}",
            )
        declarations = ast_cfg.get("declarations") if isinstance(ast_cfg.get("declarations"), list) else []
        if fixed_var and any(
            isinstance(item, Mapping)
            and EvidenceCompletionQueue._normalize_symbol(item.get("name")) == fixed_var
            and int(item.get("pointer_depth") or 0) > 0
            for item in declarations
        ):
            return EvidenceCompletionQueue._proof_from_ast(
                issue,
                outcome="reject",
                proof_kind="dynamic_array_not_fixed_storage",
                producer_engine="clang_ast_cfg_bounds",
                events=[fixed, write],
                facts=["pointer_declaration", "dynamic_array_storage"],
                summary="the indexed object is declared as dynamic pointer storage, not a fixed array",
                scope="complete intraprocedural array access path",
                subject_identity=fixed_var,
            )
        loop_expression = str(loop.get("expression") or "")
        count_match = re.search(r"<\s*([A-Za-z_]\w*)", loop_expression)
        count = count_match.group(1) if count_match else ""
        guards = ast_cfg.get("condition_guards") if isinstance(ast_cfg.get("condition_guards"), list) else []
        summary = ast_cfg.get("scope_summary") if isinstance(ast_cfg.get("scope_summary"), Mapping) else {}
        returns = summary.get("return_lines") if isinstance(summary.get("return_lines"), list) else []
        for guard in guards:
            if not isinstance(guard, Mapping):
                continue
            guard_line = int(guard.get("line") or 0)
            condition = str(guard.get("condition") or "")
            has_bound = bool(
                count
                and re.search(
                    rf"\b{re.escape(count)}\s*>\s*(?:ARRAY_SIZE\s*\(\s*{re.escape(fixed_var)}\b|[A-Z][A-Z0-9_]*)",
                    condition,
                )
            )
            if has_bound and any(guard_line < int(ret) <= guard_line + 3 for ret in returns if isinstance(ret, int)):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="array_bound_guard_dominates_loop",
                    producer_engine="clang_ast_cfg_bounds",
                    events=[fixed, {"kind": "array_bound_guard", "line": guard_line}, loop, write],
                    facts=["fixed_array_bound", "terminating_upper_bound_guard", "guard_dominates_loop"],
                    summary="a terminating array-size guard dominates the counted loop",
                    scope="complete intraprocedural fixed-array loop",
                    subject_identity=fixed_var,
                )
        return None

    @staticmethod
    def _resource_transfer_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Reject leak leads whose ownership transfer is explicit in AST facts."""

        if str(issue.get("rule") or "").lower() != "clang_cfg_acquire_without_release_on_exit":
            return None
        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
        if path.get("complete_in_function") is not True:
            return None
        acquires = [item for item in events if str(item.get("kind") or "").lower() == "acquire"]
        exits = [item for item in events if str(item.get("kind") or "").lower() == "exit"]
        for acquire in acquires:
            expression = str(acquire.get("expression") or "")
            lhs = expression.split("=", 1)[0].strip() if "=" in expression else ""
            if lhs.startswith("g_"):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="durable_global_owner_transfer",
                    producer_engine="clang_ast_cfg_ownership",
                    events=[acquire],
                    facts=["resource_stored_in_global_owner", "ownership_transfer_complete"],
                    summary="the acquired resource is stored in explicit global ownership",
                    scope="resource ownership transfer",
                    subject_identity=lhs,
                )
            if lhs.startswith("*"):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="output_parameter_ownership_transfer",
                    producer_engine="clang_ast_cfg_ownership",
                    events=[acquire],
                    facts=["resource_stored_in_output_parameter", "ownership_transfer_complete"],
                    summary="the resource is returned through an output ownership parameter",
                    scope="resource ownership transfer",
                    subject_identity=lhs,
                )
            parent = lhs.split("->", 1)[0].strip() if "->" in lhs else ""
            if parent and any(re.search(rf"\breturn\s+{re.escape(parent)}\s*;", str(exited.get("expression") or "")) for exited in exits):
                return EvidenceCompletionQueue._proof_from_ast(
                    issue,
                    outcome="reject",
                    proof_kind="returned_parent_ownership_transfer",
                    producer_engine="clang_ast_cfg_ownership",
                    events=[acquire, *exits],
                    facts=[
                        "resource_stored_in_parent",
                        "parent_returned_to_caller",
                        "ownership_transfer_complete",
                    ],
                    summary="the parent holding the resource is returned to the caller",
                    scope="resource ownership transfer",
                    subject_identity=parent,
                )
        return None

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

        ast_cfg, path, events = EvidenceCompletionQueue._ast_pack(issue)
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
        # function names, descriptions, or model prose.  The rule-specific
        # contracts below prevent an otherwise identical low-level event from
        # being reinterpreted as a different vulnerability family.
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
        direct_contracts = {
            "clang_cfg_unchecked_pointer_backtrack": {"pointer_backtrack", "backtracked_pointer_sink"},
            "clang_cfg_timer_callback_object_lock_without_scheduler_lock": {"global_scheduler_walk", "object_lock_in_callback"},
            "clang_cfg_free_derived_pointer_alias": {"pointer_derivation", "invalid_free_alias"},
            "clang_cfg_realloc_lost_original": {"realloc_assign"},
            "clang_cfg_fd_closed_without_owner_invalidation": {"fd_close"},
            "clang_cfg_requested_permission_not_applied_to_mode": {"hardcoded_permission", "requested_permission_check"},
            "clang_cfg_parsed_protocol_version_is_ignored": {"protocol_version_parse", "protocol_version_ignored"},
            "clang_cfg_raw_fd_revalidated_as_encoded": {"encoded_fd_validate", "raw_fd_derive"},
            "clang_cfg_fixed_byte_limit_before_spec_count_check": {"spec_byte_limit_mismatch"},
            "clang_cfg_path_state_key_generation_before_locked_registration": {"key_generation", "locked_registration_lookup", "path_state_check"},
            "clang_cfg_unchecked_strchr_result": {"strchr_result", "unchecked_pointer_use"},
            "clang_cfg_shared_resource_freed_without_refcount_protocol": {"free_without_refcount", "refcount_state"},
            "clang_cfg_global_dynamic_array_resize_without_lock": {"dynamic_array_publish", "dynamic_array_resize_guard"},
            "clang_cfg_size_addition_without_overflow_guard": {"integer_size_arithmetic"},
            "clang_cfg_unchecked_param_indexes_fixed_global_array": {"global_array_index"},
            "clang_cfg_full_key_lookup_truncated_key_insert": {"full_key_lookup", "truncated_key_store"},
            "clang_cfg_slot_overwrite_without_existing_owner_cleanup": {"slot_overwrite"},
            "clang_cfg_unbounded_vla_or_stack_array": {"runtime_stack_array"},
            "clang_cfg_role_specific_release_argument_mismatch": {"role_check", "role_release"},
            "clang_cfg_shell_command_concat_env": {"command_concat", "environment_source"},
            "clang_cfg_nonliteral_format_string": {"format_sink"},
            "clang_cfg_partial_aggregate_sent_with_sizeof": {"aggregate_decl", "aggregate_send"},
        }
        rule = str(issue.get("rule") or "").lower()
        matched = next((shape for shape in obligation_shapes if shape.issubset(event_kinds)), None)
        if matched is None:
            contract = direct_contracts.get(rule)
            if contract and contract.issubset(event_kinds):
                matched = contract
        if matched is None:
            return None
        code = EvidenceCompletionQueue._function_code(validation_evidence, issue)
        fact_ids = [
            f"cfg:{item.get('line')}:{item.get('kind')}"
            for item in events
            if isinstance(item, Mapping)
            and str(item.get("kind") or "").lower() in matched
            and item.get("line") not in (None, "")
        ]
        if len(fact_ids) < len(matched):
            return None
        return EvidenceCompletionQueue._proof_from_ast(
            issue,
            outcome="confirm",
            proof_kind="deterministic_cfg_obligation_path",
            producer_engine="clang_ast_cfg_obligation_prover",
            events=[
                item
                for item in events
                if str(item.get("kind") or "").lower() in matched
            ],
            facts=["source_to_sink_complete", "event_path_complete", *sorted(matched)],
            summary="deterministic AST/CFG events establish the reported safety obligation",
            scope="complete intraprocedural AST/CFG source-to-sink path",
            subject_identity=str(
                issue.get("resource_identity")
                or issue.get("source_identity")
                or issue.get("resource_signature")
                or ""
            ),
        )

    @staticmethod
    def _graph_contract_confirmation_proof(issue: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Confirm graph candidates only when their complete contract is explicit.

        Most graph leads deliberately remain reviews because their evidence is
        interprocedural and incomplete.  These two contracts carry ordered,
        source-derived graph facts sufficient to prove the violation without
        consulting a model description or an external evaluation label.
        """

        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), Mapping) else {}
        path = pack.get("path") if isinstance(pack.get("path"), Mapping) else {}
        rule = str(issue.get("rule") or "").lower()
        if path.get("complete_in_function") is not True:
            return None
        if rule == "published_before_member_initialization":
            try:
                source_line = int(path.get("source_line") or 0)
                publish_line = int(path.get("publish_line") or 0)
                late_init_line = int(path.get("late_init_line") or 0)
            except (TypeError, ValueError):
                return None
            if not (0 < source_line < publish_line < late_init_line):
                return None
            return {
                "outcome": "confirm",
                "proof_kind": "ordered_publication_before_initialization",
                "producer_engine": "graph_contract_prover",
                "proof_version": "zscope.decision-proof.v2",
                "fact_ids": [
                    f"graph_cfg:{source_line}:allocation",
                    f"graph_cfg:{publish_line}:publication",
                    f"graph_cfg:{late_init_line}:late_member_initialization",
                ],
                "cfg_nodes": [str(source_line), str(publish_line), str(late_init_line)],
                "subject_identity": str(path.get("function") or ""),
                "code_hash": EvidenceCompletionQueue._evidence_code_hash(issue, path),
                "facts": ["allocation_before_publication", "publication_before_initialization"],
                "completeness": "complete",
                "scope": "complete same-function publication lifecycle",
                "summary": "the object is published before a later member initialization",
            }
        if rule == "same_function_helper_alloc_wrapper_member_leak":
            try:
                source_line = int(path.get("source_line") or 0)
                sink_line = int(path.get("sink_line") or 0)
            except (TypeError, ValueError):
                return None
            allocation = str(path.get("allocation_function") or "")
            cleanup = str(path.get("cleanup_function") or "")
            if not (allocation and cleanup and 0 < source_line < sink_line):
                return None
            return {
                "outcome": "confirm",
                "proof_kind": "same_function_owned_member_cleanup_gap",
                "producer_engine": "graph_contract_prover",
                "proof_version": "zscope.decision-proof.v2",
                "fact_ids": [f"graph_cfg:{source_line}:wrapper_allocation", f"graph_cfg:{sink_line}:wrapper_release"],
                "cfg_nodes": [str(source_line), str(sink_line)],
                "subject_identity": f"{allocation}->{cleanup}",
                "code_hash": EvidenceCompletionQueue._evidence_code_hash(issue, path),
                "facts": ["same_function_helper_contract", "owned_member_not_released"],
                "completeness": "complete",
                "scope": "complete same-function helper allocation and cleanup path",
                "summary": "the wrapper is released while its modeled owned member is not released",
            }
        return None

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
