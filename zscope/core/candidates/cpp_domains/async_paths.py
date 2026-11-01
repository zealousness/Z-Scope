"""Bounded pthread worker witnesses, never all-interleavings safety proofs.

Reuse the concrete native CFG interpreter, source/build receipts and ObjectRef.
Only Linux LP64 direct system APIs and a same-TU callback are supported. A
successful join supplies the point at which the waiting caller is alive while
the worker resumes. Queue witnesses preserve its frame from an earlier mutex
unlock. Cancellation, removing queued pointers and stop flags do not drain it.
"""

from __future__ import annotations

from dataclasses import asdict
from functools import lru_cache
import re
from typing import Any, Generator

from .lifecycle_paths import LifecyclePaths, Frame, Pointer, Value, Unclosed, compact
from .pthread_cleanup import project_cleanup
from ....semantics.contracts import ApiContract, digest
from ....semantics.resource_identity import ObjectRef
from ....semantics.standard_api import STANDARD_API_VERSION
from ....semantics.c_linux_catalog import active_contracts

ASYNC_VERSION = "zscope.pthread-delayed-path.v9"
SYNC_SIGNATURES = {
    "pthread_mutex_init": "int(pthread_mutex_t*,constpthread_mutexattr_t*)",
    "pthread_mutex_lock": "int(pthread_mutex_t*)",
    "pthread_mutex_unlock": "int(pthread_mutex_t*)",
    "pthread_mutex_destroy": "int(pthread_mutex_t*)",
    "pthread_cond_init": "int(pthread_cond_t*,constpthread_condattr_t*)",
    "pthread_cond_signal": "int(pthread_cond_t*)",
    "pthread_cond_broadcast": "int(pthread_cond_t*)",
    "pthread_cond_destroy": "int(pthread_cond_t*)",
    "pthread_cond_wait": "int(pthread_cond_t*,pthread_mutex_t*)",
    "pthread_cond_timedwait": "int(pthread_cond_t*,pthread_mutex_t*,conststructtimespec*)",
    "pthread_cond_clockwait": "int(pthread_cond_t*,pthread_mutex_t*,int,conststructtimespec*)",
}
WAIT_APIS = {"pthread_cond_wait": 2, "pthread_cond_timedwait": 3, "pthread_cond_clockwait": 4}
SIGNATURES = {
    **SYNC_SIGNATURES,
    "malloc": "void*(unsignedlong)",
    "calloc": "void*(unsignedlong,unsignedlong)",
    "free": "void(void*)",
    "pthread_create": "int(unsignedlong*,constunionpthread_attr_t*,void*(*)(void*),void*)",
    "pthread_join": "int(unsignedlong,void**)",
    "pthread_cancel": "int(unsignedlong)",
    "pthread_detach": "int(unsignedlong)",
    "pthread_testcancel": "void(void)",
}
EFFECTS = {
    "pthread_create": "start_callback",
    "pthread_join": "wait_callback_completion",
    "pthread_cancel": "request_cancellation",
    "pthread_detach": "release_join_handle",
}


@lru_cache(maxsize=1)
def _implemented_roots() -> dict[str, str]:
    return {
        contract.symbol.name: digest(contract.to_dict())
        for row in active_contracts()
        if (contract := ApiContract.from_row({"contract": row})) is not None
        and contract.symbol.name in SIGNATURES
    }


def native_inputs_current(context: dict[str, Any]) -> bool:
    from ....retrieval.build_context import context_input_status
    from ....retrieval.indexing_identity import dependencies_current
    from ....retrieval.raii_lifecycle import native_tool_dependencies

    return context_input_status(context) == "current" and dependencies_current(
        native_tool_dependencies(context)
    )


class _WitnessStop(Exception):
    """Stop at the first invalid access; do not execute beyond undefined behavior."""


class _WorkerCancelled(Exception):
    """Successful deferred cancellation never returns to the interrupted call."""


def path_interpreter(facts: dict[str, Any]) -> type[LifecyclePaths]:
    # Discovery is deliberately restricted to an entry with a direct create.
    # Helpers containing create and indirect launchers remain with the old
    # interpreter's unknown-external-call handling.
    if any(
        e.get("callee", {}).get("name") == "pthread_create"
        for body in facts.get("functions", [])
        for e in body.get("events", [])
    ):
        return AsyncLifecyclePaths
    return LifecyclePaths


class AsyncLifecyclePaths(LifecyclePaths):

    def __init__(self, *args: Any, _wake_policy: str = "notified", **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.worker: dict[str, Any] = {}
        self.in_worker = False
        self.current_event: dict[str, Any] = {}
        self.native_event: dict[str, Any] = {}
        self.constraints: list[dict[str, Any]] = []
        self.stopped_at_access = False
        self.native_context: dict[str, Any] = {}
        self.queue_mode = False
        self.sync_address = False
        self.opaque_objects: dict[str, str] = {}
        self.sync_objects: dict[tuple[str, ...], dict[str, Any]] = {}
        self.accesses: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        self.worker_execution: Generator[tuple[Frame, dict[str, Any]], None, Value] | None = None
        self.worker_started = False
        self.waiting: dict[str, Any] = {}
        self.wait_count = 0
        self.caller_waiting: dict[str, Any] = {}
        self.caller_wait_count = 0
        self.caller_wait_frames: set[str] = set()
        self.cleanups: list[dict[str, Any]] = []
        self.in_cleanup = False
        self.cleanup_count = 0
        self.worker_stack: list[dict[str, Any]] = []
        self.worker_schedule_depth = 0
        self.helper_calls = 0
        self.wake_policy = _wake_policy
        self.unnotified_wakes = 0

    def _body(self, facts: dict[str, Any], usr: str = "") -> dict[str, Any]:
        context = facts.get("build_context") or {}
        if not context or context.get("build_context_id") != self.build:
            raise Unclosed("async_native_context_unbound")
        target = context.get("target") or {}
        if (
            target.get("target.pointer_bits") != 64
            or "-linux-" not in str(target.get("target.triple") or "")
            or target.get("target.libc") != "glibc"
        ):
            raise Unclosed("async_target_abi_unsupported")
        if self.native_context:
            if context != self.native_context:
                raise Unclosed("async_native_context_changed")
        else:
            if not native_inputs_current(context):
                raise Unclosed("async_native_inputs_stale")
            self.native_context = context
        body = super()._body(facts, usr)
        if any(
            e.get("callee", {}).get("name") in {"pthread_setcancelstate", "pthread_setcanceltype"}
            for e in body.get("events", [])
        ):
            raise Unclosed("async_cancel_mode_unsupported")
        if (
            any(e.get("callee", {}).get("name") in SYNC_SIGNATURES for e in body.get("events", []))
            and body.get("pthread_storage_facts_version") != "zscope.pthread-storage.v1"
        ):
            raise Unclosed("async_pthread_storage_receipt_missing")
        body = project_cleanup(body)
        # Keep the raw native digest above. Only this consumer projects the
        # direct system wait constants; arbitrary macros remain unclosed.
        if body.get("pthread_wait_facts_version") == "zscope.pthread-wait.v3":
            body = {
                **body,
                "events": [
                    (
                        {
                            **event,
                            "contains_macro": False,
                            "expression": event.get("pthread_wait_constant_expression")
                            or event["expression"],
                        }
                        if event.get("pthread_wait_constant_macro") is True
                        else event
                    )
                    for event in body.get("events", [])
                ],
            }
        return body

    def _opaque_storage(self, value: dict[str, Any]) -> bool:
        kind = value.get("system_record_type")
        if kind not in {"pthread_mutex_t", "pthread_cond_t"} or not value.get("usr"):
            return False
        self.opaque_objects[value["usr"]] = kind
        return True

    def _block_visit_limit(self, frame: Frame) -> int:
        # Only the worker or an actual caller-wait frame gets a bounded recheck.
        return (
            8
            if self.queue_mode and (self.in_worker or frame.invocation in self.caller_wait_frames)
            else 1
        )

    def run(self) -> dict[str, Any]:
        registry_version = self.registry.version
        first = self._run_once()
        results = [("notified", first)]
        if first["gaps"] == ["async_wait_no_matching_notification"] and self.waiting:
            policies = ["spurious_once"]
            if self.waiting.get("deadline"):
                policies.append("timeout_once")
            for policy in policies:
                interpreter = AsyncLifecyclePaths(
                    self.facts,
                    self.registry,
                    self.provider,
                    max_steps=self.max_steps,
                    max_depth=self.max_depth,
                    _wake_policy=policy,
                )
                alternative = interpreter._run_once()
                results.append((policy, alternative))
        # Prefer an actual invalid access, then a complete bounded path. None
        # of these selected schedules grants absence or universal coverage.
        selected = next((r for _, r in results if r["complete"] and r["observations"]), None)
        if selected is None:
            selected = next((r for _, r in results if r["complete"]), first)
        selected["schedule"]["wait_exploration"] = {
            "selected": next(p for p, r in results if r is selected),
            "attempts": [
                {
                    "policy": p,
                    "complete": r["complete"],
                    "gaps": r["gaps"],
                    "observations": len(r["observations"]),
                }
                for p, r in results
            ],
            "max_unsignalled_returns_per_path": 1,
            "all_outcomes_covered": False,
        }
        if self.registry.version != registry_version or (
            self.native_context and not native_inputs_current(self.native_context)
        ):
            selected.update(
                complete=False,
                observations=[],
                gaps=[*selected["gaps"], "async_inputs_changed_during_exploration"],
            )
        return selected

    def _run_once(self) -> dict[str, Any]:
        result = super().run()
        result.update(
            schema=ASYNC_VERSION,
            scope=(
                "same_tu_single_queue_pthread_witness"
                if self.queue_mode
                else "same_tu_single_delayed_pthread_witness"
            ),
            schedule={
                "kind": (
                    "worker_progress_during_caller_condition_wait_then_join"
                    if self.caller_wait_count
                    else (
                        "worker_unlock_wait_notifications_then_join"
                        if self.wait_count
                        else (
                            "worker_prefix_at_first_unlock_then_join"
                            if self.queue_mode
                            else "started_worker_delayed_until_join"
                        )
                    )
                ),
                "constraints": self.constraints,
                "worker": {
                    k: v for k, v in self.worker.items() if k not in {"body", "context", "handle"}
                },
                "stopped_at_invalid_access": self.stopped_at_access,
                "all_interleavings_covered": False,
                "failure_outcomes_covered": False,
                "absence_is_safety_proof": False,
                "condition_wait": {
                    "count": self.wait_count,
                    "pending": bool(self.waiting),
                    "notification_matched": bool(self.waiting.get("notification")),
                    "spurious_wakeups_covered": False,
                    "bounded_unsignalled_returns": self.unnotified_wakes,
                    "cancellation_cleanup_covered": bool(self.worker.get("cancelled")),
                },
                "cancellation": {
                    "mode": "default_enabled_deferred",
                    "delivered": bool(self.worker.get("cancelled")),
                    "cleanup_invocations": self.cleanup_count,
                    "pending_handlers": len(self.cleanups),
                    "all_cancellation_points_covered": False,
                },
                "helpers": {
                    "calls": self.helper_calls,
                    "scope": "same_c_file_direct_calls_heap_roots_and_scalar_values",
                    "cleanup_handler_helpers_supported": False,
                },
                "caller_condition_wait": {
                    "count": self.caller_wait_count,
                    "pending": bool(self.caller_waiting),
                    "notification_matched": bool(self.caller_waiting.get("notification")),
                    "max_waits": 4,
                    "scope": "matched_notification_cond_wait_only",
                    "implies_worker_completion": False,
                },
            },
        )
        return result

    def _run_entry(self, body: dict[str, Any]) -> None:
        try:
            super()._run_entry(body)
            if self.worker and not self.worker["complete"]:
                raise Unclosed("async_worker_not_drained_in_entry")
        except _WitnessStop:
            self.stopped_at_access = True
        if not native_inputs_current(self.native_context):
            raise Unclosed("async_native_inputs_changed_during_replay")

    def _before_event(self, frame: Frame, event: dict[str, Any]) -> None:
        self.current_event = self._site(frame, event)
        self.native_event = event

    def _after_event(self, frame: Frame, event: dict[str, Any]) -> None:
        target = event.get("assignment_target")
        if (
            not self.queue_mode
            or not target
            or event.get("event_kind") not in {"assignment", "declaration_initializer"}
        ):
            return
        value = self.memory.get(super()._location(target, frame))
        if "->" in target or (
            self.in_worker and isinstance(value, Pointer) and value in self.object_ids
        ):
            self.trace.append(
                {
                    "kind": "shared_field_store" if "->" in target else "worker_local_reference",
                    "actor": "worker" if self.in_worker else "caller",
                    "target": target,
                    "value": (
                        self.object_ids.get(value, list(value.region))
                        if isinstance(value, Pointer)
                        else value
                    ),
                    **self._site(frame, event),
                }
            )

    def _value(self, text: str, frame: Frame) -> Value:
        event = self.native_event
        if event.get("event_kind") == "statement" and compact(text) == compact(
            event.get("expression")
        ):
            declaration = re.fullmatch(r"pthread_t\s+([A-Za-z_]\w*)\s*;", str(text))
            if declaration and event.get("ast_kind") == "DeclStmt":
                name = declaration[1]
                if (
                    frame.integer_types.get(name) == (64, True)
                    and super()._location(name, frame) in self.function_locals
                ):
                    return 0  # No value is stored until successful create.
            # The native CFG may materialize a pure function-to-pointer decay
            # separately from the enclosing create call. It is not an access.
            if any(
                call.get("callee", {}).get("name") == "pthread_create"
                and call.get("block") == event.get("block")
                and len(call.get("argument_objects", [])) == 4
                and call["argument_objects"][2].get("name") == compact(text)
                and call["argument_objects"][2].get("has_definition")
                for call in frame.body.get("events", [])
            ):
                return 0
        return super()._value(text, frame)

    def _location(self, text: str, frame: Frame) -> tuple[str, ...]:
        # Only a single member selection is consumed here. The base interpreter
        # still validates the exact native field identity and value type.
        match = re.fullmatch(r"([A-Za-z_]\w*)->([A-Za-z_]\w*)", compact(text))
        if match:
            pointer = self._read(super()._location(match[1], frame))
            if isinstance(pointer, Pointer) and pointer in self.object_ids:
                super()._location(text, frame)
                resource = self.resources[self.object_ids[pointer]]
                if resource["state"] == "released":
                    if not self.in_worker:
                        raise Unclosed("non_callback_invalid_access")
                    event = {
                        "kind": "callback_access",
                        "resource_id": resource["id"],
                        **self.current_event,
                    }
                    self.trace.append(event)
                    self.observations.append(
                        {
                            "kind": "callback_after_release",
                            "resource_id": resource["id"],
                            "worker_id": self.worker["id"],
                            "event": event,
                            "release_event": resource["released_by"],
                            "ordering": (
                                "release_then_worker_access_at_"
                                + self.stack[self.worker_schedule_depth - 1]["edge_kind"]
                                if self.queue_mode
                                else "create_start_then_release_then_callback_access_during_join"
                            ),
                        }
                    )
                    raise _WitnessStop()
        elif "->" in compact(text):
            raise Unclosed("async_nested_member_unclosed")
        location = super()._location(text, frame)
        if location[-1] in self.opaque_objects:
            if not self.sync_address:
                raise Unclosed("async_opaque_storage_access")
            return location
        if (
            self.queue_mode
            and match
            and isinstance(pointer, Pointer)
            and pointer in self.object_ids
        ):
            self._shared_access(location)
        return location

    def _shared_access(self, location: tuple[str, ...]) -> None:
        actor = "worker" if self.in_worker else "caller"
        held = {key for key, value in self.sync_objects.items() if value.get("owner") == actor}
        current = {
            "actor": actor,
            "held": held,
            "concurrent": bool(self.worker) and not self.worker.get("joined", False),
        }
        # A concrete serialization alone does not legalize a C data race. This
        # conservative check even requires common protection for read/read.
        for previous in self.accesses.get(location, []):
            if (
                previous["actor"] != actor
                and previous["concurrent"]
                and current["concurrent"]
                and not (previous["held"] & held)
            ):
                raise Unclosed("async_shared_access_without_common_mutex")
        self.accesses.setdefault(location, []).append(current)

    def _standard(self, event: dict[str, Any], frame: Frame, name: str) -> None:
        callee = event.get("callee") or {}
        if (
            callee.get("usr") != "c:@F@" + name
            or callee.get("has_definition")
            or not callee.get("is_system_header")
            or not callee.get("external_linkage")
            or compact(callee.get("canonical_signature")) != SIGNATURES[name]
        ):
            raise Unclosed("async_standard_root_unverified")
        scoped = self.registry.for_context({"build_context_id": frame.body["_build_context_id"]})
        rows = scoped.find_for_call(name, file_path=frame.body["owner"]["file"])
        if len(rows) != 1:
            raise Unclosed("async_standard_contract_ambiguous")
        contract = rows[0]
        if (
            contract.source != "builtin_defaults"
            or not contract.effects_trusted
            or contract.verification.get("catalog_version") != STANDARD_API_VERSION
            or digest(contract.to_dict()) != _implemented_roots().get(name)
        ):
            raise Unclosed("async_standard_contract_unverified")
        if name in EFFECTS:
            transitions = scoped.resolved_transitions(name, event["arguments"], "0")
            if (
                len(transitions) != 1
                or transitions[0]["applicability"] != "applies"
                or [a.get("kind") for a in transitions[0]["actions"]] != [EFFECTS[name]]
            ):
                raise Unclosed("async_standard_effect_unverified")
        self.contract_inputs["standard:" + name] = {
            **contract.to_dict(),
            "contract_hash": digest(contract.to_dict()),
            "standard_root": True,
        }

    def _invoke(self, event: dict[str, Any], frame: Frame) -> Value:
        name = (event.get("callee") or {}).get("name", "")
        if event.get("pthread_cleanup"):
            return self._cleanup_operation(event, frame)
        if name in SYNC_SIGNATURES:
            return self._synchronize(event, frame, name)
        if name == "pthread_testcancel" and self.in_worker and not self.in_cleanup:
            self._standard(event, frame, name)
            self.trace.append({"kind": "deferred_cancellation_point", **self._site(frame, event)})
            if self.worker.get("cancellation_requested"):
                self._deliver_cancellation(event, frame)
            return 0
        # Ordinary worker helpers are dispatched by _invoke_steps so their
        # nested frames can suspend. Unknown points and worker allocation stay
        # unclosed; free reuses the same exact object/root checks as cleanup.
        if self.in_worker and name != "free":
            raise Unclosed("async_callback_call_or_cancellation_point")
        if name not in SIGNATURES:
            callee = event.get("callee") or {}
            if (
                callee.get("has_definition")
                and callee.get("declaration", {}).get("file") == self.file
                and not callee.get("has_attributes")
            ):
                return LifecyclePaths._invoke(self, event, frame)
            raise Unclosed("async_unknown_call")
        self._standard(event, frame, name)
        args = event.get("arguments") or []
        site = self._site(frame, event)
        if name in {"malloc", "calloc"}:
            extent = args[-1] if args else ""
            extent_match = re.fullmatch(r"sizeof\(?\*([A-Za-z_]\w*)\)?", compact(extent))
            target = event.get("object") or {}
            if (
                len(args) != (2 if name == "calloc" else 1)
                or (name == "calloc" and compact(args[0]) != "1")
                or not extent_match
                or extent_match[1] != compact(target.get("expression") or target.get("name"))
            ):
                raise Unclosed("async_allocation_extent_unclosed")
            region = ("heap:" + digest(site),)
            generation = self.generations.get(region, 0) + 1
            self.generations[region] = generation
            pointer = Pointer(region, generation)
            ref = ObjectRef(
                self.build, region[0], digest(region), digest(site), str(generation), region[0]
            )
            self.object_ids[pointer] = ref.key
            acquisition = {"kind": "acquire", "resource_id": ref.key, **site}
            self.resources[ref.key] = {
                "id": ref.key,
                "object_ref": asdict(ref),
                "build_context_id": self.build,
                "region": list(region),
                "generation": generation,
                "generation_kind": "acquisition_epoch",
                "allocation_site": site,
                "resource_family": "malloc",
                "state": "live",
                "storage": "heap",
                "release_responsibility": "unresolved",
                "acquiring_frame": frame.invocation,
                "holders": [],
                "events": [acquisition],
            }
            self.trace.append(acquisition)
            self.constraints.append({"kind": "allocation_succeeds", **site})
            if name == "calloc":
                self.zeroed.add(region)
            return pointer
        if name == "free":
            if len(args) != 1:
                raise Unclosed("async_free_arguments")
            value = self._value(args[0], frame)
            if value == 0:
                return 0
            if not isinstance(value, Pointer) or value not in self.object_ids:
                raise Unclosed("async_free_identity_unresolved")
            resource = self.resources[self.object_ids[value]]
            if resource["state"] != "live":
                raise Unclosed("async_repeat_free")
            release = {"kind": "physical_release", "resource_id": resource["id"], **site}
            resource.update(state="released", released_by=release)
            resource["events"].append(release)
            self.trace.append(release)
            return 0
        if name == "pthread_create":
            if self.worker or len(args) != 4 or self._value(args[1], frame) != 0:
                raise Unclosed("async_multiple_workers_or_attributes")
            output, context = self._value(args[0], frame), self._value(args[3], frame)
            if (
                not isinstance(output, Pointer)
                or output.region not in self.function_locals
                or not isinstance(context, Pointer)
                or context not in self.object_ids
                or self.resources[self.object_ids[context]]["state"] != "live"
            ):
                raise Unclosed("async_output_or_context_unresolved")
            objects = event.get("argument_objects") or []
            if len(objects) != 4:
                raise Unclosed("async_callback_identity_unresolved")
            callback = objects[2]
            if (
                compact(args[2]) != callback.get("name")
                or compact(callback.get("canonical_signature")) != "void*(void*)"
                or callback.get("has_attributes")
                or not callback.get("has_definition")
                or callback.get("declaration", {}).get("file") != self.file
            ):
                raise Unclosed("async_callback_identity_unresolved")
            body = self._body(
                self.provider(callback["usr"], self.file, build_context_id=self.build),
                callback["usr"],
            )
            worker_id = digest([site, callback["usr"], self.object_ids[context]])
            handle = Pointer(("pthread:" + worker_id,))
            self.memory[output.region] = handle
            self.worker = {
                "id": worker_id,
                "body": body,
                "context": context,
                "handle": handle,
                "resource_id": self.object_ids[context],
                "callback_usr": callback["usr"],
                "create_site": site,
                "complete": False,
                "detached": False,
                "cancellation_requested": False,
            }
            self.constraints.append({"kind": "pthread_create_returns_zero", **site})
            self.trace.append(
                {"kind": "callback_started_and_paused_at_entry", "worker_id": worker_id, **site}
            )
            return 0
        if not args or self._value(args[0], frame) != self.worker.get("handle"):
            raise Unclosed("async_thread_identity_unresolved")
        if self.worker.get("joined") or (self.worker["complete"] and name != "pthread_join"):
            raise Unclosed("async_thread_lifetime_ended")
        if name in {"pthread_cancel", "pthread_detach"}:
            if len(args) != 1 or (name == "pthread_detach" and self.worker["detached"]):
                raise Unclosed("async_thread_operation_invalid")
            self.worker["cancellation_requested" if name == "pthread_cancel" else "detached"] = True
            self.constraints.append({"kind": name + "_returns_zero", **site})
            self.trace.append({"kind": EFFECTS[name], "worker_id": self.worker["id"], **site})
            return 0
        if len(args) != 2 or self._value(args[1], frame) != 0 or self.worker["detached"]:
            raise Unclosed("async_join_not_available")
        self.trace.append({"kind": "join_wait_begin", "worker_id": self.worker["id"], **site})
        self._advance_worker(event, frame, pause_at_unlock=False)
        self.worker["joined"] = True
        self.constraints.append({"kind": "pthread_join_returns_zero", **site})
        self.trace.append(
            {"kind": "callback_complete_then_join_return", "worker_id": self.worker["id"], **site}
        )
        return 0

    def _advance_worker(
        self,
        event: dict[str, Any],
        frame: Frame,
        *,
        pause_at_unlock: bool,
        during_caller_wait: bool = False,
    ) -> None:
        if self.worker.get("complete"):
            return
        if self.waiting and not self._permit_wait_resume(event, frame):
            raise Unclosed("async_wait_no_matching_notification")
        if self.worker_execution is None:
            self.worker_execution = self._execution(
                self.worker["body"], [self.worker["context"]], "worker:" + self.worker["id"]
            )
        caller_stack, caller_event, native_event = self.stack, self.current_event, self.native_event
        resume_edge = {
            "caller_usr": frame.body["owner"]["usr"],
            "callee_usr": self.worker["callback_usr"],
            "caller_build_context_id": self.build,
            "callee_build_context_id": self.build,
            "event_id": event["event_id"],
            "location": event["location"],
            "edge_kind": (
                "scheduled_worker_during_caller_condition_wait"
                if during_caller_wait
                else (
                    "scheduled_worker_prefix_at_unlock"
                    if pause_at_unlock
                    else "scheduled_callback_during_join"
                )
            ),
        }
        # Keep the entry-to-caller-helper route as well as suspended worker
        # frames. Without it a helper's wait site cannot project to the entry.
        prefix = [*caller_stack, resume_edge]
        self.worker_stack[: self.worker_schedule_depth] = prefix
        self.worker_schedule_depth = len(prefix)
        self.stack = self.worker_stack
        self.in_worker = True
        self.worker_started = True
        try:
            while True:
                _, step = next(self.worker_execution)
                if self.waiting:
                    if not pause_at_unlock:
                        if self._permit_wait_resume(event, frame):
                            continue
                        raise Unclosed("async_wait_no_matching_notification")
                    break
                if pause_at_unlock and step.get("callee", {}).get("name") == "pthread_mutex_unlock":
                    self.trace.append(
                        {
                            "kind": "worker_paused_after_unlock",
                            "worker_id": self.worker["id"],
                            **self.current_event,
                        }
                    )
                    break
        except StopIteration:
            if self.cleanups:
                raise Unclosed("async_cleanup_scope_exited_without_pop") from None
            if any(value.get("owner") == "worker" for value in self.sync_objects.values()):
                raise Unclosed("async_worker_exits_with_mutex") from None
            self.worker["complete"] = True
        except _WorkerCancelled:
            self.worker["complete"] = True
            self.active_frames = {f for f in self.active_frames if not f.startswith("worker:")}
        finally:
            self.stack, self.current_event, self.native_event = (
                caller_stack,
                caller_event,
                native_event,
            )
            self.in_worker = False

    def _permit_wait_resume(self, event: dict[str, Any], frame: Frame) -> bool:
        if self.worker.get("cancellation_requested") or self.waiting.get("notification"):
            return True
        if self.unnotified_wakes or self.wake_policy == "notified":
            return False
        if self.wake_policy == "timeout_once" and not self.waiting.get("deadline"):
            return False
        self.unnotified_wakes += 1
        self.waiting["wake_reason"] = self.wake_policy
        self.trace.append(
            {
                "kind": "condition_unsignalled_wake_selected",
                "wait_id": self.waiting["id"],
                "reason": self.wake_policy,
                "deadline": self.waiting.get("deadline"),
                **self._site(frame, event),
            }
        )
        return True

    def _synchronize(self, event: dict[str, Any], frame: Frame, name: str) -> Value:
        self._standard(event, frame, name)
        self.queue_mode = True
        args = event.get("arguments") or []
        expected = WAIT_APIS.get(name, 2 if name.endswith("_init") else 1)
        if len(args) != expected:
            raise Unclosed("async_sync_arguments")
        if name in WAIT_APIS:
            return self._caller_condition_wait(event, frame, name)
        if name.endswith("_init") and self._value(args[1], frame) != 0:
            raise Unclosed("async_sync_attributes_unsupported")
        kind = "pthread_mutex_t" if name.startswith("pthread_mutex_") else "pthread_cond_t"
        key = self._sync_storage(args[0], frame, kind)
        actor = "worker" if self.in_worker else "caller"
        obj = self.sync_objects.get(key)
        if name.endswith("_init"):
            if obj is not None or self.worker:
                raise Unclosed("async_sync_initialization_unclosed")
            self.sync_objects[key] = {"kind": kind, "owner": None}
        elif obj is None:
            raise Unclosed("async_sync_not_initialized")
        elif name.endswith("_destroy"):
            if obj["owner"] or (self.worker and not self.worker.get("joined")):
                raise Unclosed("async_sync_destroy_before_join")
            del self.sync_objects[key]
        elif name == "pthread_mutex_lock":
            if obj["owner"]:
                raise Unclosed("async_mutex_would_block_or_recurse")
            obj["owner"] = actor
        elif name == "pthread_mutex_unlock":
            if obj["owner"] != actor:
                raise Unclosed("async_mutex_not_owned")
            obj["owner"] = None
        site = self._site(frame, event)
        self.constraints.append({"kind": name + "_returns_zero", **site})
        self.trace.append({"kind": name, "actor": actor, "storage": list(key), **site})
        if name in {"pthread_cond_signal", "pthread_cond_broadcast"}:
            # A signal has no saved credit. Only a currently blocked waiter on
            # this exact condition instance can receive this notification.
            matches = [
                wait
                for wait in (self.waiting, self.caller_waiting)
                if wait and key == wait["condition"] and not wait.get("notification")
            ]
            # Leave multiple-waiter recipient selection unresolved instead of
            # authorizing both returns in this bounded model.
            if len(matches) > 1 and name == "pthread_cond_signal":
                raise Unclosed("async_notification_multiple_waiters")
            for wait in matches:
                wait["notification"] = site
                self.trace.append(
                    {"kind": "condition_notification_matched", "wait_id": wait["id"], **site}
                )
        if (
            name == "pthread_mutex_unlock"
            and not self.in_worker
            and self.worker
            and (
                not self.worker_started
                or (
                    self.waiting
                    and (
                        self.waiting.get("notification")
                        or self.worker.get("cancellation_requested")
                    )
                    and self.sync_objects[self.waiting["mutex"]]["owner"] is None
                )
            )
        ):
            self._advance_worker(event, frame, pause_at_unlock=True)
        return 0

    def _caller_condition_wait(self, event: dict[str, Any], frame: Frame, name: str) -> Value:
        if name != "pthread_cond_wait" or self.in_worker or not self.worker or self.caller_waiting:
            raise Unclosed("async_caller_condition_wait_unclosed")
        if self.caller_wait_count >= 4:
            raise Unclosed("async_caller_wait_budget_exceeded")
        condition, mutex = self._wait_storage(event["arguments"], frame, "caller")
        self.caller_wait_count += 1
        self.caller_wait_frames.add(frame.invocation)
        site = self._site(frame, event)
        wait_id = digest(["caller", site, self.caller_wait_count])
        wait: dict[str, Any] = {"id": wait_id, "condition": condition, "mutex": mutex}
        self.caller_waiting = wait
        self.sync_objects[mutex]["owner"] = None
        self.trace.append(
            {
                "kind": "caller_condition_wait_releases_mutex",
                "wait_id": wait_id,
                "condition": list(condition),
                "mutex": list(mutex),
                **site,
            }
        )
        while not wait.get("notification") or self.sync_objects[mutex]["owner"] == "worker":
            if self.worker.get("complete"):
                raise Unclosed("async_caller_wait_no_matching_notification")
            # Resume only to the next unlock/wait/exit. Even a signalled caller
            # cannot reacquire a mutex while the worker still owns it.
            self._advance_worker(event, frame, pause_at_unlock=True, during_caller_wait=True)
        self._reacquire_wait(wait, "caller")
        self.trace.append(
            {
                "kind": "caller_condition_wait_reacquires_mutex",
                "wait_id": wait_id,
                "notification": wait["notification"],
                "condition": list(condition),
                "mutex": list(mutex),
                **site,
            }
        )
        self.constraints.append(
            {
                "kind": "pthread_cond_wait_returns_zero",
                "actor": "caller",
                "wait_id": wait_id,
                "result": 0,
                "wake_reason": "notification",
                **site,
            }
        )
        self.caller_waiting = {}
        # Source CFG must recheck its own predicate. A return never marks the
        # worker complete/joined or authorizes a resource/lock destruction.
        return 0

    def _wait_storage(
        self, args: list[str], frame: Frame, actor: str
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        condition = self._sync_storage(args[0], frame, "pthread_cond_t")
        mutex = self._sync_storage(args[1], frame, "pthread_mutex_t")
        if condition not in self.sync_objects or mutex not in self.sync_objects:
            raise Unclosed("async_sync_not_initialized")
        if self.sync_objects[mutex]["owner"] != actor:
            raise Unclosed("async_wait_mutex_not_owned")
        other = self.waiting if actor == "caller" else self.caller_waiting
        if other and other["condition"] == condition and other["mutex"] != mutex:
            raise Unclosed("async_condition_mutex_binding_conflict")
        return condition, mutex

    def _reacquire_wait(self, wait: dict[str, Any], actor: str) -> None:
        for key in (wait["condition"], wait["mutex"]):
            if key not in self.sync_objects or not any(
                tuple(r["region"]) == key[:1] and r["state"] == "live"
                for r in self.resources.values()
            ):
                raise Unclosed("async_wait_storage_lifetime_unclosed")
        if self.sync_objects[wait["mutex"]]["owner"]:
            raise Unclosed("async_wait_mutex_reacquire_blocked")
        self.sync_objects[wait["mutex"]]["owner"] = actor

    def _sync_storage(self, expression: str, frame: Frame, kind: str) -> tuple[str, ...]:
        self.sync_address = True
        try:
            pointer = self._value(expression, frame)
        finally:
            self.sync_address = False
        if not isinstance(pointer, Pointer) or self.opaque_objects.get(pointer.region[-1]) != kind:
            raise Unclosed("async_sync_storage_unresolved")
        # Queue synchronization storage is an opaque field of a live heap
        # context, never a union value interpreted as an ordinary record.
        if len(pointer.region) != 2 or not any(
            tuple(r["region"]) == pointer.region[:1] and r["state"] == "live"
            for r in self.resources.values()
        ):
            raise Unclosed("async_sync_storage_lifetime_unclosed")
        return pointer.region

    def _invoke_steps(
        self, event: dict[str, Any], frame: Frame
    ) -> Generator[tuple[Frame, dict[str, Any]], None, Value]:
        name = (event.get("callee") or {}).get("name", "")
        if (
            self.in_worker
            and not self.in_cleanup
            and name not in SIGNATURES
            and not event.get("pthread_cleanup")
        ):
            return (yield from self._worker_helper(event, frame))
        if name not in WAIT_APIS or not self.in_worker:
            return (yield from super()._invoke_steps(event, frame))
        if self.in_cleanup:
            raise Unclosed("async_cleanup_cancellation_point_unsupported")
        self._standard(event, frame, name)
        args = event.get("arguments") or []
        if len(args) != WAIT_APIS[name] or self.waiting:
            raise Unclosed("async_wait_arguments_unclosed")
        deadline = self._deadline(event, frame) if len(args) > 2 else None
        condition, mutex = self._wait_storage(args, frame, "worker")
        self.wait_count += 1
        site = self._site(frame, event)
        wait_id = digest([self.worker["id"], site, self.wait_count])
        self.waiting = {"id": wait_id, "condition": condition, "mutex": mutex}
        if deadline:
            self.waiting["deadline"] = deadline
        self.sync_objects[mutex]["owner"] = None
        self.trace.append(
            {
                "kind": "condition_wait_releases_mutex",
                "wait_id": wait_id,
                "condition": list(condition),
                "mutex": list(mutex),
                **site,
            }
        )
        # The native call result is not published until the generator resumes
        # with a selected wake outcome AND successful reacquisition below.
        if not self.worker.get("cancellation_requested"):
            yield frame, event
        cancelling = bool(self.worker.get("cancellation_requested"))
        if self.waiting.get("id") != wait_id or (
            not cancelling
            and not self.waiting.get("notification")
            and not self.waiting.get("wake_reason")
        ):
            raise Unclosed("async_wait_no_matching_notification")
        self._reacquire_wait(self.waiting, "worker")
        reason = self.waiting.get("wake_reason", "notification")
        result = deadline["timeout_result"] if reason == "timeout_once" and deadline else 0
        self._before_event(frame, event)
        self.trace.append(
            {
                "kind": (
                    "cancellation_reacquires_mutex"
                    if cancelling
                    else "condition_wait_reacquires_mutex"
                ),
                "wait_id": wait_id,
                "condition": list(condition),
                "mutex": list(mutex),
                "notification": self.waiting.get("notification"),
                "wake_reason": "cancellation" if cancelling else reason,
                **self.current_event,
            }
        )
        self.waiting = {}
        if cancelling:
            self._deliver_cancellation(event, frame)
        self.constraints.append(
            {
                "kind": name + ("_returns_timeout" if result else "_returns_zero"),
                "wait_id": wait_id,
                "result": result,
                "wake_reason": reason,
                "clock_constraint": (
                    {"clock": deadline["clock"], "at_or_after": deadline}
                    if deadline and result
                    else None
                ),
                **self.current_event,
            }
        )
        return result

    def _deadline(self, event: dict[str, Any], frame: Frame) -> dict[str, Any]:
        receipt = event.get("pthread_timed_wait") or {}
        values = frame.body.get("target_values") or {}
        if (
            frame.body.get("pthread_wait_facts_version") != "zscope.pthread-wait.v3"
            or receipt.get("schema") != "zscope.pthread-deadline.v3"
            or receipt.get("layout")
            != {
                "size_bytes": 16,
                "alignment_bytes": 8,
                "tv_sec_offset_bits": 0,
                "tv_nsec_offset_bits": 64,
            }
            or values.get("system.ETIMEDOUT") is not True
            or not isinstance(values.get("ETIMEDOUT"), int)
            or values["ETIMEDOUT"] <= 0
        ):
            raise Unclosed("async_timed_wait_receipt_missing")
        clock = receipt.get("clock") or {}
        explicit = event.get("callee", {}).get("name") == "pthread_cond_clockwait"
        if explicit:
            name = clock.get("name")
            if (
                clock.get("kind") != "explicit_system_constant"
                or name not in {"CLOCK_REALTIME", "CLOCK_MONOTONIC"}
                or values.get("system." + name) is not True
                or type(clock.get("value")) is not int
                or clock["value"] != values.get(name)
                or self._value(event["arguments"][2], frame) != clock["value"]
            ):
                raise Unclosed("async_wait_clock_unclosed")
        elif clock != {"kind": "condition_default", "name": "CLOCK_REALTIME"}:
            raise Unclosed("async_wait_clock_unclosed")
        expression = compact(event["arguments"][3 if explicit else 2])
        if not re.fullmatch(r"&[A-Za-z_]\w*", expression):
            raise Unclosed("async_deadline_storage_unclosed")
        pointer = self._value(expression, frame)
        root = (frame.invocation + ":" + str(receipt.get("variable_usr", "")),)
        if (
            not isinstance(pointer, Pointer)
            or pointer.region != root
            or root not in self.function_locals
        ):
            raise Unclosed("async_deadline_storage_unclosed")
        fields = receipt.get("fields") or {}
        if set(fields) != {"tv_sec", "tv_nsec"} or not all(fields.values()):
            raise Unclosed("async_deadline_fields_unclosed")
        sec, nsec = (self._read(root + (fields[n],)) for n in ("tv_sec", "tv_nsec"))
        if not (
            isinstance(sec, int)
            and 0 <= sec < 2**63
            and isinstance(nsec, int)
            and 0 <= nsec < 1000000000
        ):
            raise Unclosed("async_deadline_value_unclosed")
        return {
            "tv_sec": sec,
            "tv_nsec": nsec,
            "timeout_result": values["ETIMEDOUT"],
            "storage": list(root),
            "clock": clock["name"],
        }

    def _worker_helper(
        self, event: dict[str, Any], frame: Frame
    ) -> Generator[tuple[Frame, dict[str, Any]], None, Value]:
        target = event.get("callee") or {}
        name = target.get("name", "")
        expression = compact(event.get("expression"))
        if (
            not target.get("has_definition")
            or target.get("has_attributes")
            or target.get("is_system_header")
            or target.get("closed_targets")
            or target.get("declaration", {}).get("file") != self.file
            or not target.get("canonical_signature")
            or "..." in target["canonical_signature"]
            or not re.fullmatch(r"[A-Za-z_]\w*", name)
            or not expression.startswith(name + "(")
            or not expression.endswith(")")
        ):
            raise Unclosed("async_helper_target_unresolved")
        body = self._load(event, frame)
        definition = body.get("callable") or {}
        if (
            definition.get("has_attributes")
            or definition.get("canonical_signature") != target["canonical_signature"]
        ):
            raise Unclosed("async_helper_signature_unclosed")
        signature = compact(target["canonical_signature"])
        if signature.count("(") != 1 or not signature.endswith(")"):
            raise Unclosed("async_helper_signature_unclosed")
        parameter_types = signature.split("(", 1)[1][:-1].split(",")
        if parameter_types in (["void"], [""]):
            parameter_types = []
        args = [self._value(arg, frame) for arg in event.get("arguments", [])]
        parameters = body.get("parameters") or []
        if len(args) != len(parameter_types) or len(args) != len(parameters):
            raise Unclosed("async_helper_signature_unclosed")
        for value, kind, parameter in zip(args, parameter_types, parameters):
            self._helper_value(value, "argument")
            if not (
                (kind.endswith("*") and (value == 0 or isinstance(value, Pointer)))
                or (int(parameter.get("integer_bits") or 0) >= 32 and isinstance(value, int))
            ):
                raise Unclosed("async_helper_argument_type_unclosed")
        self.helper_calls += 1
        invocation = frame.invocation + "/helper:" + str(self.helper_calls)
        edge = {
            "caller_usr": frame.body["owner"]["usr"],
            "callee_usr": body["owner"]["usr"],
            "caller_build_context_id": self.build,
            "callee_build_context_id": self.build,
            "event_id": event["event_id"],
            "location": event["location"],
            "edge_kind": "worker_direct_helper",
            "callee_invocation": invocation,
        }
        # This list remains owned by the worker even while the scheduler uses
        # self.stack for the caller. Do not pop the caller's stack on unwind/GC.
        call_stack = self.stack
        call_stack.append(edge)
        site = self._site(frame, event)
        self.trace.append({"kind": "worker_helper_begin", "helper_invocation": invocation, **site})
        try:
            result = yield from self._execution(body, args, invocation)
            if any(h["pair"][0] == invocation for h in self.cleanups):
                raise Unclosed("async_cleanup_scope_exited_without_pop")
            self._helper_value(result, "return")
            if not (
                (
                    body["return_value_kind"] == "pointer"
                    and (result == 0 or isinstance(result, Pointer))
                )
                or (body["return_value_kind"] in {"void", "integer"} and isinstance(result, int))
            ):
                raise Unclosed("async_helper_return_type_unclosed")
            if self.in_worker:
                self._before_event(frame, event)
            self.trace.append(
                {
                    "kind": "worker_helper_return",
                    "helper_invocation": invocation,
                    "result": self.object_ids[result] if isinstance(result, Pointer) else result,
                    **self._site(frame, event),
                }
            )
            return result
        finally:
            self.active_frames.discard(invocation)
            call_stack.pop()
            if self.in_worker:
                self._before_event(frame, event)

    def _helper_value(self, value: Value, kind: str) -> None:
        if not (
            (isinstance(value, int) and -(2**31) <= value < 2**31)
            or (isinstance(value, Pointer) and value in self.object_ids)
        ):
            raise Unclosed("async_helper_" + kind + "_value_unclosed")

    def _cleanup_operation(self, event: dict[str, Any], frame: Frame) -> Value:
        if not self.in_worker or self.in_cleanup:
            raise Unclosed("async_cleanup_context_unsupported")
        marker = event["pthread_cleanup"]
        pair = frame.invocation, marker["pair"]
        if marker["action"] == "push":
            callback = marker["callback"]
            if (
                len(self.cleanups) >= 4
                or compact(callback.get("canonical_signature")) != "void(void*)"
                or not callback.get("has_definition")
                or callback.get("has_attributes")
                or callback.get("declaration", {}).get("file") != self.file
            ):
                raise Unclosed("async_cleanup_callback_unresolved")
            value = self._value(marker["argument"], frame)
            if not isinstance(value, Pointer) or value not in self.object_ids:
                raise Unclosed("async_cleanup_argument_unresolved")
            body = self._body(
                self.provider(callback["usr"], self.file, build_context_id=self.build),
                callback["usr"],
            )
            self.cleanups.append(
                {
                    "pair": pair,
                    "body": body,
                    "value": value,
                    "registration": self._site(frame, event),
                    "frame": frame,
                    "event": event,
                }
            )
            self.trace.append(
                {
                    "kind": "cleanup_registered",
                    "callback_usr": callback["usr"],
                    "resource_id": self.object_ids[value],
                    **self._site(frame, event),
                }
            )
        else:
            if not self.cleanups or self.cleanups[-1]["pair"] != pair:
                raise Unclosed("async_cleanup_stack_mismatch")
            handler = self.cleanups.pop()
            self.trace.append(
                {"kind": "cleanup_popped", "execute": marker["execute"], **self._site(frame, event)}
            )
            if marker["execute"]:
                self._run_cleanup(handler, event, frame, "normal_pop")
        return 0

    def _run_cleanup(
        self, handler: dict[str, Any], event: dict[str, Any], frame: Frame, reason: str
    ) -> None:
        self.cleanup_count += 1
        callback = handler["body"]["owner"]["usr"]
        saved_event, saved_native = self.current_event, self.native_event
        self.stack.append(
            {
                "caller_usr": frame.body["owner"]["usr"],
                "callee_usr": callback,
                "caller_build_context_id": self.build,
                "callee_build_context_id": self.build,
                "event_id": event["event_id"],
                "location": event["location"],
                "edge_kind": "pthread_cleanup_" + reason,
            }
        )
        self.trace.append(
            {
                "kind": "cleanup_begin",
                "reason": reason,
                "callback_usr": callback,
                "resource_id": self.object_ids[handler["value"]],
                "registration": handler["registration"],
                **self._site(frame, event),
            }
        )
        self.in_cleanup = True
        try:
            self._execute(
                handler["body"],
                [handler["value"]],
                frame.invocation + "/cleanup:" + str(self.cleanup_count),
            )
            self.trace.append(
                {"kind": "cleanup_end", "callback_usr": callback, **self._site(frame, event)}
            )
        finally:
            self.in_cleanup = False
            self.stack.pop()
            self.current_event, self.native_event = saved_event, saved_native

    def _deliver_cancellation(self, event: dict[str, Any], frame: Frame) -> None:
        origin = self._site(frame, event)
        self.trace.append(
            {
                "kind": "cancellation_delivered",
                "worker_id": self.worker["id"],
                **self._site(frame, event),
            }
        )
        while self.cleanups:
            handler = self.cleanups.pop()
            owner = handler["frame"]
            # Cleanup belongs to its registering frame, not necessarily the
            # helper containing the cancellation point. Preserve that origin
            # separately and project the actual unwind scope for the callback.
            depth = (
                self.worker_schedule_depth
                if owner.invocation == "worker:" + self.worker["id"]
                else next(
                    (
                        i + 1
                        for i, edge in enumerate(self.stack)
                        if edge.get("callee_invocation") == owner.invocation
                    ),
                    0,
                )
            )
            if not depth or owner.invocation not in self.active_frames:
                raise Unclosed("async_cleanup_owner_frame_unclosed")
            interrupted_stack = self.stack
            self.stack = self.stack[:depth]
            self.trace.append(
                {
                    "kind": "cleanup_unwind_scope",
                    "owner_invocation": owner.invocation,
                    "cancel_origin": origin,
                    "call_path": list(self.stack),
                }
            )
            try:
                self._run_cleanup(handler, handler["event"], owner, "cancellation")
            finally:
                self.stack = interrupted_stack
        if any(value.get("owner") == "worker" for value in self.sync_objects.values()):
            raise Unclosed("async_cancelled_worker_leaves_mutex_owned")
        self.worker["cancelled"] = True
        self.trace.append(
            {
                "kind": "cancelled_callback_complete",
                "worker_id": self.worker["id"],
                **self._site(frame, event),
            }
        )
        raise _WorkerCancelled()
