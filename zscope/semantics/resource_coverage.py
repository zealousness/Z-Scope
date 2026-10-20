"""Coverage of contract inference and resolution, independent of finding verdicts."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any, Mapping

from .build_scope import context_build_id, source_scope_problem
from .contracts import ApiContract, ContractRegistry, digest


def consumer_support(contract: ApiContract) -> dict[str, Any]:
    """Capability limits, not a claim that an enabled detector ran."""
    pattern = contract.carrier.kind == "return" and not contract.carrier.member_path
    transitions = contract.protocol.get("transitions") or []
    return {
        "contract_registry": "guarded_resolution" if contract.effects_trusted else "unverified",
        "regex": "return_pattern" if pattern else "semantic_event_only",
        "clang": "return_pattern" if pattern else "semantic_event_only",
        "graph": "return_pattern" if pattern else "semantic_event_only",
        "knowledge_db": "contract_query_not_lifetime_proof",
        "security_map": "context_event_not_lifetime_proof",
        "validator": "candidate_obligations_require_provider",
        "raii_cleanup": (
            "validator_current_native_and_ast_scoped_heap_guard; no_pattern_or_lock_authority"
            if contract.symbol.name in {"malloc", "calloc", "free"}
            and contract.source == "builtin_defaults"
            else "not_applicable"
        ),
        "lock_coverage": (
            "current_tu_static_scalar_checked_status; transparent_return_wrappers; no_recursive_wait_or_raii"
            if contract.role in {"lock", "unlock"}
            else "not_applicable"
        ),
        "async_callback": (
            "single_same_tu_linux_lp64_worker_progress_at_join_unlock_or_caller_wait; explicit_experimental_rule_only; bounded_notified_wait; bounded_c_glibc_deferred_cleanup; same_file_direct_worker_helpers; one_unsignalled_wake_or_checked_realtime_monotonic_timeout; no_cancel_mode_changes; not_all_schedules"
            if contract.symbol.name
            in {
                "pthread_create",
                "pthread_join",
                "pthread_cancel",
                "pthread_detach",
                "pthread_testcancel",
            }
            and contract.source == "builtin_defaults"
            else "not_applicable"
        ),
        "async_queue_sync": (
            "single_same_tu_heap_context_default_mutex; bounded_unlock_caller_wait_and_join; explicit_experimental_rule_only"
            if contract.symbol.name
            in {
                "pthread_mutex_init",
                "pthread_mutex_lock",
                "pthread_mutex_unlock",
                "pthread_mutex_destroy",
                "pthread_cond_init",
                "pthread_cond_signal",
                "pthread_cond_broadcast",
                "pthread_cond_destroy",
            }
            and contract.source == "builtin_defaults"
            else (
                "matching_notification_and_mutex_reacquire; bounded_c_glibc_deferred_cleanup; same_file_direct_worker_helpers; worker_one_unsignalled_wake_or_checked_realtime_monotonic_timeout; direct_system_clockwait_constants_only; no_general_deadline; explicit_experimental_rule_only; "
                + (
                    "caller_matched_wait_predicate_recheck; caller_wait_not_completion"
                    if contract.symbol.name == "pthread_cond_wait"
                    else "caller_wait_unsupported"
                )
                if contract.symbol.name
                in {"pthread_cond_wait", "pthread_cond_timedwait", "pthread_cond_clockwait"}
                and contract.source == "builtin_defaults"
                else "not_applicable"
            )
        ),
        "limitations": (["carrier_not_a_return_pattern"] if not pattern else [])
        + (["transition_requires_dedicated_consumer"] if transitions else [])
        + (
            ["lock_mode_requires_dedicated_consumer", "legacy_lockset_is_not_instance_proof"]
            if contract.role in {"lock", "unlock"}
            else []
        )
        + (
            ["nonconcurrent_pool_backed_path_only", "drop_is_not_terminal_release"]
            if contract.protocol.get("family") == "non_atomic_refcount"
            else []
        )
        + (
            [
                "bounded_handle_table_path_only",
                "function_scope_zeroed_namespace_only",
                "dup_not_same_descriptor",
                "close_status_not_release_state",
                "os_descriptor_effects_unmodeled",
            ]
            if contract.protocol.get("family") == "bounded_handle_table"
            else []
        ),
    }


def inference_coverage(
    contexts: Mapping[str, dict[str, Any]],
    snapshots: Mapping[str, dict[str, Any]],
    registry: ContractRegistry,
    *,
    scheduled: list[str] | None = None,
) -> dict[str, Any]:
    """Reuse publication inputs; do not discover, schedule or store new models.

    Rows describe resolution eligibility, not proof of detector execution. The
    scheduled graph is the denominator; unvisited cleanup is explicitly unknown.
    """
    from .contract_compiler import read_source_facts
    from .build_scope import context_symbol_usr

    interfaces: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    for identity in sorted(set(scheduled or []) | set(contexts)):
        context = contexts.get(identity, {})
        snapshot = snapshots.get(identity, {})
        scoped = registry.for_context(context)
        # The interface lookup resolves the context's own native owner
        # receipt: a published pinned contract is only "source_verified" for
        # the exact symbol the current facts name, and incomplete, stale, or
        # conflicting receipts stay unknown instead of matching by name.
        published = scoped.find_for_call(
            str(context.get("func_name") or ""),
            file_path=str(context.get("file_path") or ""),
            usr=context_symbol_usr(context),
        )
        reasons = sorted(
            {
                str(e)
                for row in snapshot.get("contract_diagnostics", [])
                for e in row.get("errors", [])
            }
        )
        scope_problem = source_scope_problem(context)
        if not context:
            status = "not_seen"
            reasons.append("scheduled_context_unavailable")
        elif scope_problem:
            status = "stale/conflict"
            reasons.append(scope_problem)
        elif any(c.effects_trusted and c.source.startswith("inferred") for c in published):
            status = "source_verified"
        elif any(c.effects_trusted and c.source != "builtin_defaults" for c in published):
            status = "manual_assumption"
        elif published:
            status = "schema_only"
        elif snapshot.get("raw_interface_contracts"):
            status = "proposed"
        else:
            status = "unsupported"
            reasons.append("no_published_contract" if snapshot else "model_unavailable")
        interfaces.append(
            {
                "symbol": identity,
                "build_context_id": context_build_id(context),
                "native_usr": (
                    (context.get("program_facts") or {}).get("function_identity") or {}
                ).get("usr", ""),
                "proposal_origin": (
                    "model_proposal"
                    if snapshot.get("raw_interface_contracts")
                    else (
                        "static_derivation"
                        if snapshot.get("snapshot_kind") == "syntactic"
                        else "none_recorded"
                    )
                ),
                "status": status,
                "reasons": reasons,
                "contracts": [
                    {
                        "symbol": asdict(c.symbol),
                        "role": c.role,
                        "source": c.source,
                        "verifier": c.verification.get("method", "manual_declaration"),
                        "checker": c.verification.get("checker", ""),
                        "authority": "must_under_guard" if c.effects_trusted else "unverified",
                        "consumers": consumer_support(c),
                        "carrier": asdict(c.carrier),
                        "contract_hash": digest(c.to_dict()),
                    }
                    for c in published
                ],
            }
        )
        if not context:
            continue
        source = read_source_facts(context, scoped)
        resolved = scoped.trace_calls(context, source_facts=source)
        for row in resolved:
            calls.append(
                {
                    **row,
                    "coverage_reason": row.get("unknown_reason")
                    or (
                        "resolved_effect_not_detector_execution"
                        if row["applicability"] == "applies"
                        else "condition_unchecked_or_not_satisfied"
                    ),
                }
            )
        unknown_sites: list[tuple[str, dict[str, Any]]] = [
            (
                call.name,
                {
                    "token_offset": call.token_offset,
                    "guard": call.guard,
                    "occurrence": call.occurrence,
                },
            )
            for call in source.opaque_calls
        ]
        located_names = {name for name, _ in unknown_sites}
        unknown_sites.extend(
            (name, {"site_unavailable": True})
            for name in sorted(source.unknown_calls - located_names)
        )
        for name, site in unknown_sites:
            calls.append(
                {
                    **site,
                    "caller": identity,
                    "file_path": context.get("file_path"),
                    "build_context_id": context_build_id(context),
                    "callee": name,
                    "applicability": "unknown",
                    "coverage_reason": (
                        "project_shadows_standard"
                        if name in scoped.shadowed_symbols
                        else "contract_missing_or_unverified"
                    ),
                }
            )
        if not source.complete:
            calls.append(
                {
                    "caller": identity,
                    "build_context_id": context_build_id(context),
                    "applicability": "unknown",
                    "coverage_reason": "source_flow_incomplete",
                }
            )
        if not (context.get("program_facts") or {}).get("complete"):
            calls.append(
                {
                    "caller": identity,
                    "build_context_id": context_build_id(context),
                    "applicability": "unknown",
                    "coverage_reason": "native_receipt_unavailable",
                }
            )
    # A call can have several effects; effect rows must not be called unique sites.
    counts = dict(sorted(Counter(row["status"] for row in interfaces).items()))
    return {
        "schema": "zscope.resource-inference-coverage.v1",
        "interfaces": interfaces,
        "calls": calls,
        "interface_counts": counts,
        "call_effect_rows": len(calls),
        "scope": "scheduled_graph",
        "outside_entry_cleanup_coverage": "not_measured",
        "consumer_execution": "see_engine_coverage_and_rule_catalog",
        "finding_verdict_authority": False,
    }
