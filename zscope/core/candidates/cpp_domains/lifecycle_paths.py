"""Bounded execution of native C CFGs for object-protocol path observations.

Only concrete paths with exact TU/link receipts are interpreted. Unknown input, aliasing, calls or
control flow stop the path; they are never guessed or treated as cleanup.
Acquisition epochs are analysis identities, not the program's wrapping counter.
These observations carry no proof authority and do not invent business ownership.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Callable, Generator, cast

from ....semantics.build_scope import bind_build_scope, source_scope_problem
from ....semantics.contracts import ApiContract, ContractRegistry, code_tokens, digest
from ....semantics.resource_identity import HandleValue, ObjectRef
from .handle_paths import HandleTracker

PATH_VERSION = "zscope.object-protocol-path.v5"


def observation_facts(
    result: dict[str, Any], observation: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    """S04: expose only discharged path facts; keep business obligations open."""
    resource = next(r for r in result["resources"] if r["id"] == observation["resource_id"])
    facts = [
        {"kind": "protocol_acquisition", "site": resource["allocation_site"]},
        {
            "kind": "object_generation",
            "region": resource["region"],
            "generation": resource["generation"],
            "generation_kind": "acquisition_epoch",
        },
        {
            "kind": "feasible_lifecycle_path",
            "cfg_path": result["cfg_path"],
            "inputs": result["inputs"],
        },
        {"kind": "protocol_observation", "observation": observation},
    ]
    required = ["event:" + fact["kind"] for fact in facts] + ["event:business_release_requirement"]
    if any(e["kind"].startswith("refcount_") for e in result["trace"]):
        required.append("event:nonconcurrent_reference_count")
    if any(e["kind"].startswith("handle_") for e in result["trace"]):
        required.append("event:serial_handle_namespace")
    if observation["kind"] in {"failed_retention_unreleased", "handle_left_live"}:
        required.append("event:responsibility_endpoint")
    if observation["kind"] == "released_reference_retained":
        required.append("event:later_slot_access")
    for fact in facts:
        fact["object"] = resource["id"]
        fact["proof_authority"] = False
    return facts, required


class Unclosed(Exception):
    """A required native fact or supported operation is unavailable."""


@dataclass(frozen=True)
class Pointer:
    region: tuple[str, ...]
    generation: int = 0


Value = int | Pointer | HandleValue


@dataclass
class Frame:
    body: dict[str, Any]
    invocation: str
    variables: dict[str, str] = field(default_factory=dict)
    fields: dict[str, str] = field(default_factory=dict)
    calls: dict[str, Value] = field(default_factory=dict)
    unsigned: set[str] = field(default_factory=set)
    records: set[str] = field(default_factory=set)
    integer_types: dict[str, tuple[int, bool]] = field(default_factory=dict)


def compact(value: Any) -> str:
    return "".join(code_tokens(str(value or "")))


def address(value: Value) -> Any:
    # C pointer equality compares addresses, not saved acquisition provenance.
    if isinstance(value, HandleValue):
        return value.value
    return value.region if isinstance(value, Pointer) else value


class LifecyclePaths:
    """One bounded entry execution, with exact callee and invocation identity."""

    def __init__(
        self,
        facts: dict[str, Any],
        registry: ContractRegistry,
        provider: Callable[..., dict[str, Any]],
        *,
        max_steps: int = 512,
        max_depth: int = 12,
    ):
        self.facts, self.registry, self.provider = facts, registry, provider
        self.build = str(facts.get("build_context_id") or "")
        self.file = str((facts.get("functions") or [{}])[0].get("owner", {}).get("file") or "")
        self.max_steps, self.max_depth = max_steps, max_depth
        self.steps = 0
        self.memory: dict[tuple[str, ...], Value] = {}
        self.zeroed: set[tuple[str, ...]] = set()
        self.generations: dict[tuple[str, ...], int] = {}
        self.resources: dict[str, dict[str, Any]] = {}
        self.object_ids: dict[Pointer, str] = {}
        self.trace: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self.stack: list[dict[str, Any]] = []
        self.cache: dict[str, dict[str, Any]] = {}
        self.observations: list[dict[str, Any]] = []
        self.inputs: dict[str, str] = {}
        self.contract_inputs: dict[str, dict[str, Any]] = {}
        self.function_bindings: dict[str, dict[str, str]] = {}
        self.link_target: dict[str, Any] = {}
        self.link_resolver: Any = None
        self.handles = HandleTracker(self)
        self.active_frames: set[str] = set()
        self.function_locals: set[tuple[str, ...]] = set()

    def run(self) -> dict[str, Any]:
        gaps: list[str] = []
        try:
            body = self._body(self.facts)
            self._run_entry(body)
            if self.link_target and not self.link_resolver.current(self.link_target["target_id"]):
                raise Unclosed("link_inputs_changed_during_path")
        except Unclosed as exc:
            gaps.append(str(exc))
        # End-of-entry is an analysis boundary, not automatically the end of a
        # long-lived receiver's responsibility. Keep that obligation explicit.
        if not gaps:
            for resource in self.resources.values():
                pointer = Pointer(tuple(resource["region"]), resource["generation"])
                resource["holders_at_exit"] = [
                    holder
                    for holder in resource["holders"]
                    if self.memory.get(tuple(holder)) == pointer
                ]
                if (
                    resource["state"] == "live"
                    and resource.get("retention_failed")
                    and not resource["holders_at_exit"]
                ):
                    self.observations.append(
                        {
                            "kind": "failed_retention_unreleased",
                            "resource_id": resource["id"],
                            "event": resource["retention_failed"],
                            "effect": "still_live_at_entry_exit",
                        }
                    )
                if (
                    resource["state"] == "released"
                    and resource["holders_at_exit"]
                    and not any(o["resource_id"] == resource["id"] for o in self.observations)
                ):
                    self.observations.append(
                        {
                            "kind": "released_reference_retained",
                            "resource_id": resource["id"],
                            "event": resource["released_by"],
                        }
                    )
        handle_objects = self.handles.finish() if not gaps else []
        return {
            "schema": PATH_VERSION,
            "build_context_id": self.build,
            "entry_usr": (self.facts.get("functions") or [{}])[0].get("owner", {}).get("usr"),
            "complete": not gaps,
            "gaps": gaps,
            "proof_authority": False,
            "scope": (
                "concrete_linked_c_entry_path"
                if self.link_target
                else "concrete_same_tu_entry_path"
            ),
            "link_target": self.link_target,
            "function_bindings": self.function_bindings,
            "inputs": self.inputs,
            "contract_inputs": self.contract_inputs,
            "trace": self.trace,
            "cfg_path": self.edges,
            "resources": list(self.resources.values()),
            "handle_objects": handle_objects,
            # A prefix cannot certify the eventual absence of cleanup.
            "observations": self.observations if not gaps else [],
            "steps": self.steps,
        }

    def _run_entry(self, body: dict[str, Any]) -> None:
        self._execute(body, [], "entry")

    def _before_event(self, frame: Frame, event: dict[str, Any]) -> None:
        pass

    def _after_event(self, frame: Frame, event: dict[str, Any]) -> None:
        pass

    def _opaque_storage(self, value: dict[str, Any]) -> bool:
        return False

    def _block_visit_limit(self, frame: Frame) -> int:
        return 1

    def _invoke_steps(
        self, event: dict[str, Any], frame: Frame
    ) -> Generator[tuple[Frame, dict[str, Any]], None, Value]:
        # Ordinary calls run synchronously; async consumers may suspend a call
        # before it returns without inventing a return value in the frame.
        yield from ()
        return self._invoke(event, frame)

    def _invoke(self, event: dict[str, Any], frame: Frame) -> Value:
        callee = self._load(event, frame)
        call_args = [self._value(a, frame) for a in event.get("arguments") or []]
        call_site = self._site(frame, event)
        self.stack.append(
            {
                "caller_usr": frame.body["owner"]["usr"],
                "callee_usr": callee["owner"]["usr"],
                "caller_build_context_id": frame.body["_build_context_id"],
                "callee_build_context_id": callee["_build_context_id"],
                "event_id": event["event_id"],
                "location": event.get("location"),
            }
        )
        call_site["call_path"] = list(self.stack)
        value = self._execute(
            callee, call_args, frame.invocation + "/" + event["event_id"], call_site
        )
        self.stack.pop()
        return value

    def _body(self, facts: dict[str, Any], usr: str = "") -> dict[str, Any]:
        bodies = facts.get("functions") or []
        build = str(facts.get("build_context_id") or "")
        linked = build in self.link_target.get("members", [])
        if (
            not self.build
            or source_scope_problem({"program_facts": facts})
            or (build != self.build and not linked)
            or not facts.get("complete")
            or len(bodies) != 1
        ):
            raise Unclosed("incomplete_or_mismatched_build")
        body = bodies[0]
        owner = body.get("owner") or {}
        if (
            not body.get("complete")
            or body.get("fact_version") != "zscope.program-events.v5"
            or body.get("resource_protocol_facts_version") != "zscope.resource-protocol-facts.v1"
            or body.get("lifecycle_value_facts_version") != "zscope.lifecycle-value-facts.v1"
            or not owner.get("usr")
            or (usr and owner["usr"] != usr)
            or (not linked and owner.get("file") != self.file)
            or not str(owner.get("file") or "").endswith(".c")
        ):
            raise Unclosed("unresolved_native_function_identity")
        identity = build + ":" + owner["usr"]
        self.inputs[identity] = digest(body)
        self.function_bindings[identity] = {
            "build_context_id": build,
            "usr": owner["usr"],
            "file": owner["file"],
        }
        if (
            body.get("return_value_kind") not in {"pointer", "integer", "void"}
            or 0 < int(body.get("return_integer_bits") or 0) < 32
        ):
            raise Unclosed("return_conversion_unclosed")
        return {**body, "_build_context_id": build}

    def _load(self, call: dict[str, Any], frame: Frame) -> dict[str, Any]:
        callee = call.get("callee") or {}
        targets = callee.get("closed_targets")
        if targets:
            if (
                frame.body.get("linkage_facts_version") != "zscope.c-linkage.v1"
                or targets.get("schema") != "zscope.const-call-targets.v1"
            ):
                raise Unclosed("indirect_target_receipt_unavailable")
            selection = self._value(targets.get("selection", ""), frame)
            choices = targets.get("targets") or []
            if not isinstance(selection, int) or not 0 <= selection < len(choices) <= 8:
                raise Unclosed("indirect_selection_unresolved")
            callee = choices[selection]
        usr = str(callee.get("usr") or "")
        build, source = frame.body["_build_context_id"], frame.body["owner"]["file"]
        if not usr:
            raise Unclosed("external_or_indirect_call")
        key = build + ":" + usr
        if key not in self.cache:
            try:
                if (
                    callee.get("has_definition")
                    and (callee.get("declaration") or {}).get("file") == source
                ):
                    facts = self.provider(usr, source, build_context_id=build)
                else:
                    factory = getattr(
                        getattr(self.provider, "__self__", None), "linked_targets", None
                    )
                    if not callable(factory):
                        raise Unclosed("external_or_indirect_call")
                    if self.link_resolver is None:
                        self.link_resolver = factory()
                    facts = self.link_resolver.resolve(
                        build, usr, self.link_target.get("target_id", "")
                    )
                    if not facts.get("complete"):
                        raise Unclosed(str(facts.get("reason") or "linked_callee_unavailable"))
                    self.link_target = facts["link_target"]
                    self.inputs["link:" + self.link_target["target_id"]] = digest(self.link_target)
            except (TypeError, KeyError, ValueError):
                raise Unclosed("exact_callee_facts_unavailable") from None
            body = self._body(facts, usr)
            if facts.get("link_target"):
                definition = body.get("callable") or {}
                if (
                    body.get("linkage_facts_version") != "zscope.c-linkage.v1"
                    or not definition.get("external_linkage")
                    or definition.get("has_attributes")
                    or not callee.get("external_linkage")
                    or callee.get("has_attributes")
                    or not callee.get("canonical_signature")
                    or callee["canonical_signature"] != definition.get("canonical_signature")
                    or not callee.get("record_layouts_complete")
                    or not definition.get("record_layouts_complete")
                    or callee.get("record_layouts") != definition.get("record_layouts")
                ):
                    raise Unclosed("callee_linkage_or_signature_unclosed")
            self.cache[key] = body
        return self.cache[key]

    def _frame(self, body: dict[str, Any], invocation: str) -> Frame:
        frame = Frame(body, invocation)
        values = list(body.get("parameters") or [])
        for event in body.get("events") or []:
            values += list(event.get("defs") or []) + list(event.get("uses") or [])
            values += list(event.get("argument_objects") or []) + [event.get("object") or {}]
            for uses in event.get("argument_uses") or []:
                values += uses
        for edge in body.get("cfg_edges") or []:
            values += list(edge.get("condition_uses") or [])
        for value in values:
            if not value:
                continue
            if (
                value.get("pointee_record_kind") == "union" or value.get("overlapping_storage")
            ) and not self._opaque_storage(value):
                raise Unclosed("union_aliasing")
            if value.get("volatile_or_atomic"):
                raise Unclosed("concurrent_value_unclosed")
            if value.get("bit_field"):
                raise Unclosed("bit_field_unclosed")
            if value.get("floating_value") or 0 < int(value.get("integer_bits") or 0) < 32:
                raise Unclosed("scalar_conversion_unclosed")
            key = compact(value.get("expression") or value.get("name"))
            if value.get("integer_unsigned"):
                frame.unsigned.add(key)
            if bits := int(value.get("integer_bits") or 0):
                integer_type = (bits, bool(value.get("integer_unsigned")))
                if key in frame.integer_types and frame.integer_types[key] != integer_type:
                    raise Unclosed("conflicting_integer_type")
                frame.integer_types[key] = integer_type
            if value.get("record_value"):
                frame.records.add(key)
            usr = value.get("usr")
            kind = value.get("value_kind")
            if usr and kind == "local" and value.get("function_scope_local") is True:
                self.function_locals.add((invocation + ":" + usr,))
            target = frame.fields if kind == "field" else frame.variables
            if kind not in {"field", "local", "parameter"} or not usr or not key:
                continue
            if key in target and target[key] != usr:
                raise Unclosed("ambiguous_native_object")
            target[key] = usr
        return frame

    def _read(self, location: tuple[str, ...]) -> Value:
        if location in self.memory:
            return self.memory[location]
        if any(location[: len(root)] == root for root in self.zeroed):
            return 0
        raise Unclosed("unknown_object_value")

    def _location(self, text: str, frame: Frame) -> tuple[str, ...]:
        text = compact(text)
        match = re.fullmatch(r"([A-Za-z_]\w*)((?:(?:->|\.)[A-Za-z_]\w*)*)", text)
        if not match or match[1] not in frame.variables:
            raise Unclosed("unsupported_object_expression")
        prefix = match[1]
        location: tuple[str, ...] = (frame.invocation + ":" + frame.variables[prefix],)
        for operator, member in re.findall(r"(->|\.)([A-Za-z_]\w*)", match[2]):
            if operator == "->":
                pointer = self._read(location)
                if not isinstance(pointer, Pointer):
                    raise Unclosed("unknown_or_null_receiver")
                location = pointer.region
            prefix += operator + member
            if prefix not in frame.fields:
                raise Unclosed("missing_native_field_identity")
            location += (frame.fields[prefix],)
        return location

    def _value(self, text: str, frame: Frame) -> Value:
        text = compact(text)
        if text == "((void*)0)":
            return 0
        if text.startswith("(void)"):
            self._value(text[6:], frame)
            return 0
        # Split only outside parentheses, retaining C short circuit semantics.
        for operators in (("||",), ("&&",), ("==", "!="), ("<=", ">=", "<", ">")):
            depth = 0
            for i, char in enumerate(text):
                if char == "(":
                    depth += 1
                if char == ")":
                    depth -= 1
                if depth:
                    continue
                op = next((op for op in operators if text.startswith(op, i)), "")
                if not op:
                    continue
                if op == ">" and i and text[i - 1] == "-":
                    continue  # A member arrow is not a relational operator.
                left = self._value(text[:i], frame)
                if op == "||" and left:
                    return 1
                if op == "&&" and not left:
                    return 0
                right = self._value(text[i + len(op) :], frame)
                if op in {"&&", "||"}:
                    return int(bool(right))
                if op in {"<", ">", "<=", ">="}:
                    left = left.value if isinstance(left, HandleValue) else left
                    right = right.value if isinstance(right, HandleValue) else right
                    if not isinstance(left, int) or not isinstance(right, int):
                        raise Unclosed("pointer_order_unclosed")
                    return int(
                        {
                            "<": left < right,
                            ">": left > right,
                            "<=": left <= right,
                            ">=": left >= right,
                        }[op]
                    )
                return int((address(left) == address(right)) == (op == "=="))
        if text.startswith("(") and text.endswith(")"):
            return self._value(text[1:-1], frame)
        if re.fullmatch(r"-?\d+", text):
            number = int(text)
            if not -(2**31) <= number < 2**31:
                raise Unclosed("integer_range_unclosed")
            return number
        if text.startswith("!"):
            return int(not self._value(text[1:], frame))
        if text.startswith("&"):
            return Pointer(self._location(text[1:], frame))
        if text in frame.calls:
            return frame.calls[text]
        if text in frame.records:
            raise Unclosed("aggregate_value_copy_unclosed")
        return self._read(self._location(text, frame))

    def _site(self, frame: Frame, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "function_usr": frame.body["owner"]["usr"],
            "build_context_id": frame.body["_build_context_id"],
            "invocation": frame.invocation,
            "event_id": event["event_id"],
            "location": event.get("location"),
            "expression": event.get("expression"),
            "call_path": list(self.stack),
        }

    def _contract(self, body: dict[str, Any]) -> ApiContract | None:
        build = body["_build_context_id"]
        # The body's native owner identity is verified by ``_body``; the
        # publication must carry exactly that USR.  A record whose USR was
        # blanked or forged never authorizes the effect, even when its name,
        # file, build and verification metadata all match.
        with bind_build_scope({"build_context_id": build}):
            rows = self.registry.find_for_call(
                body["owner"]["name"],
                file_path=body["owner"]["file"],
                usr=str(body["owner"].get("usr") or ""),
            )
        if len(rows) != 1:
            return None
        row = rows[0]
        contract = (
            row
            if (
                row.status == "active"
                and row.effects_trusted
                and row.symbol.build_context_id == build
                and row.verification.get("method") == "source_protocol"
                and row.protocol.get("family")
                in {
                    "single_slot_pool",
                    "single_slot_retention",
                    "non_atomic_refcount",
                    "bounded_handle_table",
                }
            )
            else None
        )
        if contract is not None:
            self.contract_inputs[build + ":" + body["owner"]["usr"]] = {
                "function_usr": body["owner"]["usr"],
                "symbol": asdict(contract.symbol),
                "contract_hash": digest(contract.to_dict()),
                "source": contract.source,
                "verification": contract.verification,
                "evidence": contract.evidence,
            }
        return contract

    def _binding(
        self, contract: ApiContract, body: dict[str, Any], frame: Frame, path: str
    ) -> tuple[str, ...]:
        binding = contract.resource_domain
        if binding is None or binding.argument_index is None:
            raise Unclosed("missing_protocol_domain")
        parameter = body["parameters"][binding.argument_index]["name"]
        return self._location(parameter + path, frame)

    def _protocol_before(
        self, contract: ApiContract | None, body: dict[str, Any], args: list[Value], frame: Frame
    ) -> dict[str, Any]:
        if contract is None:
            return {}
        if contract.protocol["family"] == "bounded_handle_table":
            return self.handles.before(contract, body, args, frame)
        if contract.protocol["family"] == "non_atomic_refcount":
            index = contract.carrier.argument_index
            if index is None or index >= len(args) or not isinstance(args[index], Pointer):
                raise Unclosed("refcount_object_unresolved")
            pointer = args[index]
            assert isinstance(pointer, Pointer)
            saved = self._resource(pointer)
            current = self.generations.get(pointer.region, 0)
            resource = self._resource(Pointer(pointer.region, current))
            if saved is None or resource is None:
                raise Unclosed("refcount_acquisition_unresolved")
            location = self._location(
                body["parameters"][index]["name"] + contract.protocol["count_path"], frame
            )
            if location != pointer.region + (contract.protocol["count_field_usr"],):
                raise Unclosed("refcount_member_identity_unclosed")
            old = self._read(location)
            if not isinstance(old, int) or not -(2**31) <= old < 2**31:
                raise Unclosed("refcount_value_unclosed")
            resource.setdefault("reference_counts", {})[contract.protocol["count_field_usr"]] = {
                "location": list(location),
                "value": old,
            }
            return {
                "count_location": location,
                "old_count": old,
                "pointer": pointer,
                "saved": saved,
                "resource": resource,
                "current_generation": current,
                "was_released": resource["state"] == "released",
                "trace_start": len(self.trace),
            }
        if contract.protocol["family"] == "single_slot_pool":
            identity = contract.protocol["pool_identity"]
            slot = self._binding(contract, body, frame, identity["slot_path"])
            live = self._binding(contract, body, frame, identity["live_path"])
            return {"slot": slot, "live": live, "was_live": self._read(live)}
        action = contract.protocol["transitions"][0]["actions"][0]
        slot = self._binding(contract, body, frame, action["new"]["member_path"])
        return {"slot": slot, "previous": self._read(slot)}

    def _resource(self, pointer: Pointer) -> dict[str, Any] | None:
        return self.resources.get(self.object_ids.get(pointer, ""))

    def _protocol_after(
        self,
        contract: ApiContract | None,
        before: dict[str, Any],
        args: list[Value],
        result: Value,
        site: dict[str, Any],
    ) -> Value:
        if contract is None:
            return result
        if contract.protocol["family"] == "bounded_handle_table":
            return self.handles.after(contract, before, args, result, site)
        if contract.protocol["family"] == "non_atomic_refcount":
            return self._refcount_after(contract, before, result, site)
        slot = before["slot"]
        if contract.role == "allocator" and isinstance(result, Pointer):
            if result.region != slot or before["was_live"] != 0 or self._read(before["live"]) != 1:
                raise Unclosed("pool_effect_mismatch")
            generation = self.generations.get(slot, 0) + 1
            self.generations[slot] = generation
            result = Pointer(slot, generation)
            object_ref = ObjectRef(
                site["build_context_id"],
                slot[-1],
                digest(slot),
                digest(site),
                str(generation),
                slot[-1],
            )
            uid = object_ref.key
            self.object_ids[result] = uid
            event = {"kind": "acquire", "resource_id": uid, **site}
            self.trace.append(event)
            self.resources[uid] = {
                "id": uid,
                "object_ref": asdict(object_ref),
                "build_context_id": site["build_context_id"],
                "region": list(slot),
                "generation": generation,
                "generation_kind": "acquisition_epoch",
                "allocation_site": site,
                "resource_family": contract.resource_family,
                "state": "live",
                "storage": "embedded_slot",
                "release_responsibility": "unresolved",
                "acquiring_frame": site["invocation"],
                "holders": [],
                "events": [event],
            }
            return result
        index = contract.carrier.argument_index
        if index is None or index >= len(args) or not isinstance(args[index], Pointer):
            return result
        pointer = args[index]
        assert isinstance(pointer, Pointer)
        resource = self._resource(pointer)
        if resource is None:
            raise Unclosed("unknown_acquisition_generation")
        if contract.role == "deallocator":
            current = self.generations.get(slot, 0)
            applies = pointer.region == slot and bool(before["was_live"])
            status = contract.protocol.get("return_status")
            if status and result != status["success" if applies else "failure"]:
                raise Unclosed("pool_return_status_mismatch")
            if applies and self._read(before["live"]) != 0:
                raise Unclosed("pool_release_effect_mismatch")
            event = {
                "kind": "release_attempt",
                **site,
                "resource_id": resource["id"],
                "domain": list(slot[:-1]),
                "saved_generation": pointer.generation,
                "current_generation": current,
                "effect_applies": applies,
            }
            self.trace.append(event)
            resource["events"].append(event)
            if pointer.region != slot:
                self.observations.append(
                    {"kind": "wrong_pool_return", "resource_id": resource["id"], "event": event}
                )
            elif pointer.generation != current:
                self.observations.append(
                    {
                        "kind": "stale_generation_return",
                        "resource_id": resource["id"],
                        "event": event,
                    }
                )
            elif resource["state"] == "released":
                self.observations.append(
                    {"kind": "repeat_return", "resource_id": resource["id"], "event": event}
                )
            if applies:
                actual = self._resource(Pointer(slot, current))
                if actual is None:
                    raise Unclosed("unknown_current_generation")
                counts = [
                    self._read(tuple(row["location"]))
                    for row in actual.get("reference_counts", {}).values()
                ]
                if any(isinstance(value, int) and value > 0 for value in counts):
                    self.observations.append(
                        {
                            "kind": "release_with_live_references",
                            "resource_id": actual["id"],
                            "event": event,
                            "reference_counts": counts,
                        }
                    )
                actual["state"] = "released"
                actual["released_by"] = event
        elif contract.role == "reference_retention":
            success = contract.protocol["transitions"][0]["when"]["right"]["value"]
            retained = result == success
            if retained and self._read(slot) != pointer:
                raise Unclosed("retention_effect_mismatch")
            if not retained and self._read(slot) != before["previous"]:
                raise Unclosed("retention_failure_changed_slot")
            event = {
                "kind": "retain_reference" if retained else "retention_failed",
                **site,
                "resource_id": resource["id"],
                "holder": list(slot),
                "return_value": result,
                "ownership_transfer_proven": False,
            }
            self.trace.append(event)
            resource["events"].append(event)
            if retained:
                resource["holders"].append(list(slot))
            else:
                resource["retention_failed"] = event
                resource["responsibility_observation"] = "no_transfer_on_failure"
        return result

    def _refcount_after(
        self, contract: ApiContract, before: dict[str, Any], result: Value, site: dict[str, Any]
    ) -> Value:
        operation = contract.protocol["operation"]
        old, new = before["old_count"], self._read(before["count_location"])
        applies = operation == "init" or (old > 0 and (operation != "retain" or old < 2**31 - 1))
        expected = (
            1
            if operation == "init"
            else old + ((1 if operation == "retain" else -1) if applies else 0)
        )
        if new != expected or (operation != "init" and result != int(applies)):
            raise Unclosed("refcount_effect_mismatch")
        resource, saved = before["resource"], before["saved"]
        terminal = operation == "drop" and applies and old == 1
        release = resource.get("released_by")
        released_here = release is not None and release in self.trace[before["trace_start"] :]
        event = {
            "kind": "refcount_" + operation,
            **site,
            "resource_id": resource["id"],
            "saved_resource_id": saved["id"],
            "before": old,
            "after": new,
            "effect_applies": applies,
            "zero_transition": terminal,
            "terminal_effect": (
                "logical_pool_return" if terminal and released_here else "none_observed"
            ),
            "concurrency": "requires_nonconcurrent_context",
        }
        resource["reference_counts"][contract.protocol["count_field_usr"]]["value"] = new
        self.trace.append(event)
        resource["events"].append(event)
        kind = ""
        if before["pointer"].generation != before["current_generation"]:
            kind = "stale_generation_refcount"
        elif before["was_released"]:
            kind = "refcount_after_return"
        elif terminal and resource["state"] == "live":
            kind = "zero_count_unreleased"
        if kind:
            self.observations.append({"kind": kind, "resource_id": saved["id"], "event": event})
        return result

    def _execute(
        self,
        body: dict[str, Any],
        args: list[Value],
        invocation: str,
        site: dict[str, Any] | None = None,
    ) -> Value:
        execution = self._execution(body, args, invocation, site)
        while True:
            try:
                next(execution)
            except StopIteration as done:
                return cast(Value, done.value)

    def _execution(
        self,
        body: dict[str, Any],
        args: list[Value],
        invocation: str,
        site: dict[str, Any] | None = None,
    ) -> Generator[tuple[Frame, dict[str, Any]], None, Value]:
        """Retain a native frame across bounded scheduler cut points."""
        if len(self.stack) >= self.max_depth or any(
            s["callee_usr"] == body["owner"]["usr"] for s in self.stack[:-1]
        ):
            raise Unclosed("call_depth_or_recursion_bound")
        parameters = body.get("parameters") or []
        if len(parameters) != len(args):
            raise Unclosed("entry_inputs_unresolved")
        frame = self._frame(body, invocation)
        self.active_frames.add(invocation)
        for parameter, argument in zip(parameters, args):
            self._check_handle_type(argument, parameter["name"], frame)
            if parameter["name"] in frame.unsigned and isinstance(argument, int) and argument < 0:
                raise Unclosed("scalar_conversion_unclosed")
            self.memory[self._location(parameter["name"], frame)] = argument
        contract = self._contract(body) if site else None
        before = self._protocol_before(contract, body, args, frame)
        edges = body.get("cfg_edges") or []
        blocks = {e["from"] for e in edges} | {e["to"] for e in edges}
        entry, exit_block = body.get("cfg_entry"), body.get("cfg_exit")
        if (
            not isinstance(entry, int)
            or not isinstance(exit_block, int)
            or entry not in blocks
            or exit_block not in blocks
        ):
            raise Unclosed("unsupported_cfg_shape")
        block = entry
        visited: dict[int, int] = {}
        result: Value = 0
        events = body.get("events") or []
        if any(not e.get("event_id") or e.get("block") not in blocks for e in events) or len(
            {e["event_id"] for e in events}
        ) != len(events):
            raise Unclosed("incomplete_event_identity")
        while block != exit_block:
            if visited.get(block, 0) >= self._block_visit_limit(frame):
                raise Unclosed("loop_path_unclosed")
            visited[block] = visited.get(block, 0) + 1
            frame.calls.clear()
            seen: set[tuple[Any, ...]] = set()
            for event in sorted(
                (e for e in events if e["block"] == block), key=lambda e: e["ordinal"]
            ):
                self.steps += 1
                if self.steps > self.max_steps:
                    raise Unclosed("path_step_bound")
                kind = event.get("event_kind")
                if kind == "call":
                    key = (
                        event.get("location", {}).get("offset"),
                        event.get("callee", {}).get("usr"),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    copies = [
                        e
                        for e in events
                        if e["block"] == block
                        and e.get("event_kind") == "call"
                        and (e.get("location", {}).get("offset"), e.get("callee", {}).get("usr"))
                        == key
                    ]
                    primary = [e for e in copies if e.get("contains_macro") is False]
                    if len(primary) != 1:
                        raise Unclosed("ambiguous_call_site")
                    event = primary[0]
                null_store = (
                    kind == "assignment"
                    and compact(event.get("assignment_value")) == "((void*)0)"
                    and compact(event.get("expression"))
                    == compact(event.get("assignment_target")) + "=NULL"
                )
                null_return = (
                    kind == "return" and compact(event.get("return_value")) == "((void*)0)"
                )
                if event.get("contains_macro") is not False and not (null_store or null_return):
                    raise Unclosed("macro_operation_unclosed")
                self._before_event(frame, event)
                if kind == "call":
                    value = yield from self._invoke_steps(event, frame)
                    frame.calls[compact(event["expression"])] = value
                    target = event.get("object") or {}
                    if target.get("usr"):
                        self._check_handle_type(
                            value, target.get("expression") or target["name"], frame
                        )
                        if (
                            compact(target.get("expression") or target.get("name"))
                            in frame.unsigned
                            and isinstance(value, int)
                            and value < 0
                        ):
                            raise Unclosed("scalar_conversion_unclosed")
                        self.memory[
                            self._location(target.get("expression") or target["name"], frame)
                        ] = value
                elif kind in {"assignment", "declaration_initializer"}:
                    location = self._location(event["assignment_target"], frame)
                    value_text = compact(event["assignment_value"])
                    if value_text == "{0}":
                        self.zeroed.add(location)
                    else:
                        value = self._value(value_text, frame)
                        self._check_handle_type(value, event["assignment_target"], frame)
                        if (
                            compact(event["assignment_target"]) in frame.unsigned
                            and isinstance(value, int)
                            and value < 0
                        ):
                            raise Unclosed("scalar_conversion_unclosed")
                        self.memory[location] = value
                elif kind == "increment_decrement":
                    expression = compact(event["expression"])
                    if not expression.endswith(("++", "--")):
                        raise Unclosed("unsupported_integer_operation")
                    location = self._location(expression[:-2], frame)
                    old = self._read(location)
                    integer_type = frame.integer_types.get(expression[:-2])
                    if not isinstance(old, int) or integer_type is None:
                        raise Unclosed("integer_type_unclosed")
                    bits, unsigned = integer_type
                    lower, upper = (
                        (0, 2**bits - 1) if unsigned else (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1)
                    )
                    new = old + (1 if expression.endswith("++") else -1)
                    if (
                        not 32 <= bits <= 64
                        or not lower <= old <= upper
                        or not lower <= new <= upper
                    ):
                        raise Unclosed("integer_range_unclosed")
                    self.memory[location] = new
                elif kind == "return":
                    result = (
                        self._value(event["return_value"], frame)
                        if event.get("return_value")
                        else 0
                    )
                elif kind == "statement":
                    # Validate pure guard expression; do not ignore hidden effects.
                    pure_targets = (
                        {
                            compact(target.get(key))
                            for call in events
                            if call.get("block") == block
                            if (target := (call.get("callee") or {}).get("closed_targets"))
                            and target.get("schema") == "zscope.const-call-targets.v1"
                            for key in ("base", "expression")
                        }
                        if body.get("linkage_facts_version") == "zscope.c-linkage.v1"
                        else set()
                    )
                    if compact(event["expression"]) not in pure_targets:
                        self._value(event["expression"], frame)
                else:
                    raise Unclosed("unsupported_native_event:" + str(kind))
                self._after_event(frame, event)
                yield frame, event
            outgoing = [e for e in edges if e["from"] == block]
            selected = []
            for edge in outgoing:
                condition = edge.get("condition")
                if not condition and len(outgoing) == 1:
                    selected.append(edge)
                elif condition and edge.get("branch") in {"true", "false"}:
                    if bool(self._value(condition, frame)) == (edge["branch"] == "true"):
                        selected.append(edge)
                else:
                    raise Unclosed("unknown_cfg_branch")
            if len(selected) != 1:
                raise Unclosed("ambiguous_cfg_path")
            self.edges.append(
                {
                    "function_usr": body["owner"]["usr"],
                    "build_context_id": body["_build_context_id"],
                    "invocation": invocation,
                    **{key: selected[0][key] for key in ("from", "to", "condition", "branch")},
                }
            )
            block = selected[0]["to"]
        if isinstance(result, HandleValue) and (
            body.get("return_value_kind") != "integer"
            or body.get("return_integer_bits") != 32
            or body.get("return_integer_unsigned")
        ):
            raise Unclosed("handle_conversion_unclosed")
        if body.get("return_integer_unsigned") and isinstance(result, int) and result < 0:
            raise Unclosed("return_conversion_unclosed")
        result = self._protocol_after(contract, before, args, result, site) if site else result
        self.handles.end_frame(invocation)
        self.active_frames.remove(invocation)
        return result

    @staticmethod
    def _check_handle_type(value: Value, expression: str, frame: Frame) -> None:
        if isinstance(value, HandleValue) and frame.integer_types.get(compact(expression)) != (
            32,
            False,
        ):
            raise Unclosed("handle_conversion_unclosed")
