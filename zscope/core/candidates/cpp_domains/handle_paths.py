"""Integer descriptor identities inside the existing concrete CFG execution.

Only source-checked, bounded table protocols are interpreted. Every operation
checks the actual table before and after execution. Backing identity shared by
dup is not proof of physical destruction when its last descriptor is consumed.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, TYPE_CHECKING

from ....semantics.contracts import ApiContract, digest
from ....semantics.resource_identity import HandleValue, ObjectRef

if TYPE_CHECKING:
    from .lifecycle_paths import Frame, LifecyclePaths, Value


class HandleTracker:
    def __init__(self, path: LifecyclePaths):
        self.path = path
        self.spaces: dict[tuple[str, ...], str] = {}
        self.current: dict[tuple[tuple[str, ...], int], str] = {}
        self.backing: dict[tuple[tuple[str, ...], int], dict[str, Any]] = {}

    def before(
        self, contract: ApiContract, body: dict[str, Any], args: list[Value], frame: Frame
    ) -> dict[str, Any]:
        from .lifecycle_paths import Pointer, Unclosed

        if not args or not isinstance(args[0], Pointer):
            raise Unclosed("handle_namespace_unresolved")
        namespace = args[0].region
        if (
            namespace not in self.path.zeroed
            or namespace not in self.path.function_locals
            or not any(
                namespace[0].startswith(invocation + ":") for invocation in self.path.active_frames
            )
        ):
            raise Unclosed("handle_namespace_lifetime_unclosed")
        identity = contract.protocol["table_identity"]
        if namespace in self.spaces and self.spaces[namespace] != digest(identity):
            raise Unclosed("handle_table_identity_conflict")
        self.spaces[namespace] = digest(identity)
        locations, state = {}, {}
        for slot in identity["slots"]:
            number = slot["value"]
            pair = tuple(
                self.path._binding(contract, body, frame, slot[key])
                for key in ("live_path", "object_path")
            )
            if pair != (namespace + (slot["live_usr"],), namespace + (slot["object_usr"],)):
                raise Unclosed("handle_field_identity_mismatch")
            live, token = (self.path._read(p) for p in pair)
            if (
                type(live) is not int
                or type(token) is not int
                or live not in (0, 1)
                or not 0 <= token < 2**31
            ):
                raise Unclosed("handle_table_value_unclosed")
            uid = self.current.get((namespace, number))
            if bool(uid) != bool(live) or (not live and token != 0):
                raise Unclosed("handle_table_state_untracked")
            if uid and token != self.path.resources[uid]["backing_token"]:
                raise Unclosed("handle_backing_identity_untracked")
            locations[number], state[number] = pair, (live, token)
        operation = contract.protocol["operation"]
        saved = args[1] if operation != "open" else None
        if operation != "open" and not isinstance(saved, HandleValue):
            if type(saved) is not int or saved >= 0:
                raise Unclosed("handle_acquisition_provenance_unknown")
        sequence_location = None
        sequence = 0
        if operation == "open":
            sequence_location = self.path._binding(
                contract, body, frame, contract.protocol["sequence_path"]
            )
            sequence_value = self.path._read(sequence_location)
            if type(sequence_value) is not int or not 0 <= sequence_value < 2**31:
                raise Unclosed("handle_sequence_unclosed")
            sequence = sequence_value
        if operation == "close" and type(args[2]) is not int:
            raise Unclosed("handle_failure_input_unclosed")
        number = saved.value if isinstance(saved, HandleValue) else saved
        return {
            "namespace": namespace,
            "locations": locations,
            "state": state,
            "sequence_location": sequence_location,
            "sequence": sequence,
            "saved": saved,
            "number": number,
            "actual_id": (
                self.current.get((namespace, number), "") if isinstance(number, int) else ""
            ),
        }

    def after(
        self,
        contract: ApiContract,
        before: dict[str, Any],
        args: list[Value],
        result: Value,
        site: dict[str, Any],
    ) -> Value:
        from .lifecycle_paths import Unclosed

        operation = contract.protocol["operation"]
        namespace, state = before["namespace"], before["state"]
        expected = dict(state)
        target, backing_token = None, 0
        actual_id = before["actual_id"]
        if operation == "open":
            if before["sequence"] < 2**31 - 1:
                target = next((n for n, (live, _) in state.items() if not live), None)
            expected_result = target if target is not None else -1
            sequence = before["sequence"] + int(target is not None)
            if self.path._read(before["sequence_location"]) != sequence:
                raise Unclosed("handle_sequence_effect_mismatch")
            if target is not None:
                backing_token = sequence
                expected[target] = (1, backing_token)
                if (namespace, backing_token) in self.backing:
                    raise Unclosed("handle_backing_token_reused")
        elif operation == "dup":
            if actual_id:
                target = next((n for n, (live, _) in state.items() if not live), None)
                backing_token = state[before["number"]][1]
            expected_result = target if target is not None else -1
            if target is not None:
                expected[target] = (1, backing_token)
        else:
            failed = bool(args[2])
            consumes = bool(actual_id) and (
                not failed or contract.protocol["close_failure"] == "consumes"
            )
            expected_result = 0 if actual_id and not failed else -1
            if consumes:
                expected[before["number"]] = (0, 0)
        after = {
            n: tuple(self.path._read(p) for p in pair) for n, pair in before["locations"].items()
        }
        if type(result) is not int or result != expected_result or after != expected:
            raise Unclosed("handle_effect_mismatch")
        saved = before["saved"]
        saved_id = saved.resource_id if isinstance(saved, HandleValue) else ""
        event = {
            "kind": "handle_" + operation,
            **site,
            "namespace": list(namespace),
            "saved_resource_id": saved_id,
            "actual_resource_id": actual_id,
            "return_value": result,
            "consumed": operation == "close" and consumes,
            "effect_applies": target is not None if operation != "close" else consumes,
            "concurrency": "requires_serial_handle_namespace",
        }
        if saved_id:
            resource = self.path.resources[saved_id]
            kind = ""
            if saved.namespace != namespace:
                kind = "wrong_handle_namespace"
            elif actual_id and saved_id != actual_id:
                kind = "stale_handle_generation"
            elif resource["state"] == "released":
                kind = "closed_handle_operation"
            if kind:
                self.path.observations.append(
                    {"kind": kind, "resource_id": saved_id, "event": event}
                )
            resource["events"].append(event)
        if operation == "close" and consumes:
            current = self.path.resources[actual_id]
            current.update(state="released", released_by=event)
            self.current.pop((namespace, before["number"]))
        if target is not None:
            region = namespace + ("handle:" + str(target),)
            epoch = self.path.generations.get(region, 0) + 1
            self.path.generations[region] = epoch
            object_ref = ObjectRef(
                site["build_context_id"],
                contract.protocol["table_identity"]["table_type_usr"],
                digest(region),
                digest(site),
                str(epoch),
            )
            key = (namespace, backing_token)
            if operation == "open":
                backing_ref = ObjectRef(
                    site["build_context_id"],
                    object_ref.symbol_usr,
                    digest([namespace, "backing"]),
                    digest(site),
                    str(backing_token),
                )
                self.backing[key] = {
                    "id": backing_ref.key,
                    "object_ref": asdict(backing_ref),
                    "namespace": list(namespace),
                    "physical_destruction": "unproven",
                }
            backing = self.backing[key]
            uid = object_ref.key
            event.update(resource_id=uid, backing_object_id=backing["id"], generation=epoch)
            self.path.resources[uid] = {
                "id": uid,
                "object_ref": asdict(object_ref),
                "build_context_id": site["build_context_id"],
                "region": list(region),
                "namespace": list(namespace),
                "handle_value": target,
                "generation": epoch,
                "generation_kind": "acquisition_epoch",
                "allocation_site": site,
                "resource_family": contract.resource_family,
                "state": "live",
                "storage": "integer_handle",
                "release_responsibility": "unresolved",
                "acquiring_frame": site["invocation"],
                "holders": [],
                "events": [event],
                "backing_token": backing_token,
                "backing_object_id": backing["id"],
                "duplicated_from": actual_id if operation == "dup" else "",
            }
            self.current[(namespace, target)] = uid
            result = HandleValue(target, namespace, uid)
        self.path.trace.append(event)
        return result

    def finish(self) -> list[dict[str, Any]]:
        for resource in self.path.resources.values():
            if resource["storage"] == "integer_handle" and resource["state"] == "live":
                self.path.observations.append(
                    {
                        "kind": "handle_left_live",
                        "resource_id": resource["id"],
                        "event": resource["events"][-1],
                        "effect": "descriptor_live_at_entry_exit",
                    }
                )
        return [
            {
                **obj,
                "live_descriptors": [
                    uid
                    for uid in self.current.values()
                    if self.path.resources[uid]["backing_object_id"] == obj["id"]
                ],
            }
            for obj in self.backing.values()
        ]

    def end_frame(self, invocation: str) -> None:
        from .lifecycle_paths import Unclosed

        # Only the selected entry's endpoint can remain a business premise.
        # An inner frame cannot export a live descriptor from its expired table.
        if invocation != "entry" and any(
            r["storage"] == "integer_handle"
            and r["state"] == "live"
            and r["namespace"][0].startswith(invocation + ":")
            for r in self.path.resources.values()
        ):
            raise Unclosed("handle_namespace_lifetime_unclosed")
