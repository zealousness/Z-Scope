from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from zscope.orchestration.primitive_contract_proposals import (
    _proposal_rows,
    proposal_packets,
    propose_contracts,
    _public_batch,
    _proposal_batches,
)
from zscope.orchestration.primitive_discovery import (
    _object_path,
    _macro_arguments,
    _remap_macro_value,
    _merge_variants,
)
from zscope.retrieval.instance_index import InstanceScope


def test_recovered_initial_response_still_requires_semantic_review(tmp_path):
    work, roots = setup(tmp_path)

    class Model:
        calls = 0

        def chat_completion(self, messages, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return {"choices": [{"finish_reason": "length", "message": {"content": ""}}]}
            value = contract(json.loads(messages[1]["content"]))
            if self.calls == 2:
                result = {"contracts": [value]}
            else:
                assert messages[-2]["role"] == "assistant"
                result = {"changes": [], "add": []}
            return {"choices": [{"message": {"content": json.dumps(result)}}]}

    model = Model()
    rows, audit = propose_contracts(
        model, work={"a": work["a"]}, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert model.calls == 3 and rows and audit["reviewed"] == 1


def test_overwritten_guard_member_needs_entry_identity_and_cfg_order():
    from zscope.orchestration.primitive_boundary_evidence import overwritten_entry_member

    param = {"name": "owner", "usr": "p:owner"}
    member = {"name": "buffer", "usr": "f:buffer", "expression": "owner->buffer"}
    body = {
        "complete": True,
        "parameters": [param],
        "cfg_entry": 2,
        "cfg_edges": [{"from": 2, "to": 1}, {"from": 1, "to": 0}],
        "events": [
            {
                "event_kind": "call",
                "block": 1,
                "ordinal": 1,
                "object": {"expression": "owner->buffer"},
                "arguments": ["size"],
            },
            {
                "event_kind": "call",
                "block": 1,
                "ordinal": 2,
                "arguments": ["owner->buffer"],
                "uses": [member],
            },
        ],
    }
    assert overwritten_entry_member(body, "owner->buffer")
    # A prior condition on the old field is real entry evidence.
    body["cfg_edges"][0]["condition_uses"] = [member]
    assert not overwritten_entry_member(body, "owner->buffer")
    body["cfg_edges"][0].pop("condition_uses")
    # Passing the parent to an unknown helper before the overwrite can read it.
    body["events"].insert(
        0, {"event_kind": "call", "block": 2, "ordinal": 1, "arguments": ["owner"]}
    )
    assert not overwritten_entry_member(body, "owner->buffer")
    body["events"].pop(0)
    # A saved alias can observe the entry field after the direct overwrite.
    body["events"].insert(
        0,
        {
            "event_kind": "declaration",
            "block": 2,
            "ordinal": 1,
            "assignment_target": "saved",
            "assignment_value": "owner",
            "uses": [param],
        },
    )
    assert not overwritten_entry_member(body, "owner->buffer")
    body["events"].pop(0)
    body["events"][0]["arguments"] = ["owner->buffer"]
    assert not overwritten_entry_member(body, "owner->buffer")


def test_only_native_unambiguous_globals_get_bare_guard_alias(tmp_path):
    from zscope.orchestration.primitive_boundary_evidence import native_guard_globals
    from zscope.orchestration.primitive_contract_proposals import _guard

    body = {
        "cfg_edges": [
            {
                "condition_uses": [
                    {
                        "name": "threshold",
                        "usr": "global:limit",
                        "value_kind": "global",
                        "integer_bits": 32,
                    }
                ]
            }
        ]
    }
    names = native_guard_globals(body)
    assert _guard("level >= threshold", ["level"], globals=names) == _guard(
        "level >= global.threshold", ["level"]
    )
    assert _guard("threshold", [], globals=names)["right"]["value"] == 0
    body["events"] = [
        {"uses": [{"name": "threshold", "usr": "local:limit", "value_kind": "local"}]}
    ]
    assert not native_guard_globals(body)
    with pytest.raises(ValueError, match="unobservable"):
        _guard("threshold", [], globals=native_guard_globals(body))


def test_field_context_is_native_anchored_bounded_and_project_local(tmp_path):
    from zscope.orchestration.primitive_boundary_evidence import field_declarations

    source = tmp_path / "shape.h"
    source.write_text("struct Data {\nunsigned char output[128];\n};\n")
    record = {
        "name": "output",
        "usr": "field:output",
        "value_kind": "field",
        "expression": "data->output",
        "declaration": {"file": str(source), "line": 2},
    }
    body = {"events": [{"uses": [record, record]}]}
    assert field_declarations(body, tmp_path) == [
        {"expression": "data->output", "declaration": "unsigned char output[128];"}
    ]
    record["declaration"]["line"] = 1
    assert not field_declarations(body, tmp_path)
    record["declaration"]["file"] = str(tmp_path.parent / "foreign.h")
    assert not field_declarations(body, tmp_path)


@pytest.mark.parametrize(
    "spelling,deref,writable",
    [
        ("const char *", 0, False),
        ("const char **", 0, True),
        ("const char **", 1, False),
        ("char * const *", 0, False),
        ("char * const *", 1, True),
        ("char ** const", 0, True),
        ("const char ***", 0, True),
        ("const char ***", 1, True),
        ("const char ***", 2, False),
    ],
)
def test_output_slot_const_is_checked_at_selected_indirection(tmp_path, spelling, deref, writable):
    from zscope.orchestration.primitive_contract_proposals import _check_object_type

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    packet["_item"][2]["functions"][0]["parameters"][0]["type"] = spelling
    value = {"role": "copy", "carrier": {"root": "argument", "index": 0, "dereference": deref}}
    if writable:
        _check_object_type(value, packet)
    else:
        with pytest.raises(ValueError, match="selected pointer level"):
            _check_object_type(value, packet)


def test_delta_removal_preserves_other_roles_and_requires_source_accounting():
    from zscope.orchestration.primitive_boundary_evidence import apply_review_delta

    old = {"contracts": [{"role": "lock"}, {"role": "unlock"}, {"role": "standard_operation"}]}
    edits = {
        "changes": [
            {"index": 0, "contract": None, "reason": "balanced at return", "evidence_refs": ["n0"]},
            {"index": 1, "contract": None, "reason": "balanced at return", "evidence_refs": ["n0"]},
        ]
    }
    assert apply_review_delta(edits, old, {"n0"})["contracts"] == [{"role": "standard_operation"}]
    assert len(old["contracts"]) == 3
    edits["changes"][0]["evidence_refs"] = ["foreign"]
    with pytest.raises(ValueError, match="allowed source"):
        apply_review_delta(edits, old, {"n0"})
    edits["changes"][0]["evidence_refs"] = ["n0"]
    edits["changes"].append(edits["changes"][0])
    with pytest.raises(ValueError, match="exactly once"):
        apply_review_delta(edits, old, {"n0"})


def test_delta_source_binding_can_reuse_claim_but_roots_cannot_replace_source():
    from zscope.orchestration.primitive_boundary_evidence import apply_review_delta

    old = {"contracts": [{"role": "copy", "evidence_refs": ["n0", "r:0"]}]}
    change = {
        "changes": [{"index": 0, "contract": None, "reason": "source shows only bookkeeping"}]
    }
    result = apply_review_delta(change, old, {"n0"}, {"r:0"})
    assert result["contracts"] == []
    assert result["review_edits"][0]["evidence_binding"] == "previous_clause"
    change["changes"][0]["evidence_refs"] = ["r:0"]
    with pytest.raises(ValueError, match="allowed source"):
        apply_review_delta(change, old, {"n0"}, {"r:0"})
    change["changes"][0]["evidence_refs"] = ["n0", "foreign"]
    with pytest.raises(ValueError, match="allowed source"):
        apply_review_delta(change, old, {"n0"}, {"r:0"})


def test_replacement_rationale_is_a_reason_not_a_required_duplicate_envelope():
    from zscope.orchestration.primitive_boundary_evidence import apply_review_delta

    old = {"contracts": [{"role": "format_sink", "guard": "true", "evidence_refs": ["n0"]}]}
    replacement = {
        "role": "format_sink",
        "guard": "level >= global.limit",
        "rationale": "early level gate",
        "evidence_refs": ["n0"],
    }
    result = apply_review_delta({"changes": [{"index": 0, "contract": replacement}]}, old, {"n0"})
    assert result["contracts"] == [replacement]
    assert result["review_edits"][0]["reason"] == "early level gate"


def test_delta_replacement_refs_expand_and_are_revalidated(tmp_path):
    work, roots = setup(tmp_path)

    class Model:
        calls = 0

        def chat_completion(self, messages, **kwargs):
            self.calls += 1
            packet = json.loads(messages[1]["content"])
            value = contract(packet)
            if self.calls == 1:
                value["carrier"] = {"root": "argument", "index": 999}
                result = {"contracts": [value]}
            else:
                result = {
                    "changes": [
                        {
                            "index": 0,
                            "contract": value,
                            "reason": "actual returned allocation",
                            "evidence_refs": [packet["id"]],
                        }
                    ]
                }
            return {"choices": [{"message": {"content": json.dumps(result)}}]}

    model = Model()
    rows, audit = propose_contracts(
        model, work={"a": work["a"]}, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert model.calls == 2 and audit["reviewed"] == 1 and not audit["errors"]
    assert rows[0]["status"] == "pending"


def test_invalid_delta_reference_diagnostic_uses_request_local_ids(tmp_path):
    work, roots = setup(tmp_path)
    full_id = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0][
        "id"
    ]

    class Model:
        calls = 0

        def chat_completion(self, messages, **kwargs):
            self.calls += 1
            packet = json.loads(messages[1]["content"])
            if self.calls == 1:
                result = {"contracts": [contract(packet)]}
            elif self.calls == 2:
                result = {
                    "changes": [
                        {
                            "index": 0,
                            "contract": None,
                            "reason": "check reference",
                            "evidence_refs": ["n999"],
                        }
                    ]
                }
            else:
                diagnostic = messages[-1]["content"]
                assert "received=['n999']" in diagnostic and "source=['n0']" in diagnostic
                assert full_id not in diagnostic
                result = {
                    "changes": [],
                    "reason": "Original source still supports returned allocation",
                }
            return {"choices": [{"message": {"content": json.dumps(result)}}]}

    model = Model()
    rows, audit = propose_contracts(
        model, work={"a": work["a"]}, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert model.calls == 3 and rows and audit["reviewed"] == 1


@pytest.mark.parametrize("revive", [False, True])
def test_schema_repair_cannot_restart_semantic_discovery(tmp_path, revive):
    work, roots = setup(tmp_path)

    class Model:
        calls = 0

        def chat_completion(self, messages, **kwargs):
            self.calls += 1
            packet = json.loads(messages[1]["content"])
            good = contract(packet)
            if self.calls == 1:
                result = {"contracts": [good]}
            elif self.calls == 2:
                bad = {**good, "carrier": {"root": "argument", "index": 999}}
                result = {"changes": [], "add": [bad]}
            else:
                assert "Repair ONLY rejected indices" in messages[-1]["content"]
                assert "GUARANTEE CHECKLIST" not in messages[-1]["content"]
                result = {
                    "changes": [
                        {
                            "index": 1,
                            "contract": None,
                            "reason": "No such caller argument",
                            "evidence_refs": [packet["id"]],
                        }
                    ],
                    "add": [good] if revive else [],
                }
            return {"choices": [{"message": {"content": json.dumps(result)}}]}

    model = Model()
    rows, audit = propose_contracts(
        model, work={"a": work["a"]}, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert model.calls == 3 and len(rows) == 1
    assert audit["reviewed"] == (0 if revive else 1)
    assert bool(audit["errors"]) == revive


def test_review_compaction_preserves_current_witness_not_old_overall_explanations():
    from zscope.orchestration.primitive_boundary_evidence import compact_draft

    draft = {
        "results": [
            {
                "id": "one",
                "reason": "long explanation",
                "contracts": [
                    {
                        "role": "copy",
                        "object": "out",
                        "guard": "return == 0",
                        "else": "unknown",
                        "strength": "may",
                        "evidence_refs": ["node"],
                        "rationale": "long explanation",
                    }
                ],
            }
        ]
    }
    result = compact_draft(draft)
    assert result["results"][0]["contracts"][0] == draft["results"][0]["contracts"][0]
    assert "reason" not in result["results"][0]
    assert draft["results"][0]["reason"] == "long explanation"


def test_request_aliases_are_lossless_local_and_do_not_rewrite_source(tmp_path):
    from zscope.orchestration.primitive_boundary_evidence import (
        compact_evidence_ids,
        map_proposal_refs,
    )

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    public = _public_batch([packet])
    public["nodes"][0]["code"] += " /* " + public["id"] + " */"
    transport, bindings = compact_evidence_ids(public)
    assert transport["id"] == "n0"
    assert transport["nodes"][0]["code"] == public["nodes"][0]["code"]
    assert len(json.dumps(transport)) < len(json.dumps(public))
    value = contract(transport)
    expanded = map_proposal_refs({"id": "n0", "contracts": [value]}, bindings)
    assert expanded["id"] == packet["id"]
    assert _proposal_rows(expanded["contracts"], packet, tmp_path)
    value["evidence_refs"] = ["n999"]
    with pytest.raises(ValueError, match="source node"):
        _proposal_rows(
            map_proposal_refs({"contracts": [value]}, bindings)["contracts"], packet, tmp_path
        )
    assert value["evidence_refs"] == ["n999"]


def test_boundary_observations_distinguish_slots_and_literal_format():
    from zscope.orchestration.primitive_boundary_evidence import boundary_observations

    body = {
        "parameters": [{"name": "record"}, {"name": "out"}],
        "events": [
            {
                "event_kind": "assignment",
                "assignment_target": "record->items",
                "assignment_value": "NULL",
            },
            {"event_kind": "call", "callee": {"name": "make"}, "object": {"expression": "*out"}},
            {
                "event_kind": "call",
                "callee": {"name": "render", "usr": "root:render"},
                "arguments": ["dst", '"literal %s"', "data"],
            },
        ],
    }
    roots = [
        {
            "role": "format_sink",
            "symbol": {"name": "render", "usr": "root:render"},
            "carrier": {"kind": "argument", "argument_index": 1},
        }
    ]
    assert boundary_observations(body, roots) == [
        {"write_slot": "record->items", "value": "NULL"},
        {"call_result_slot": "*out", "callee": "make"},
        {"format_operand": '"literal %s"', "callee": "render"},
    ]
    body["events"][-1]["callee"]["usr"] = "shadow:render"
    assert len(boundary_observations(body, roots)) == 2


def test_null_callback_must_registration_rejected_but_conditional_kept(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import (
        _check_object_type,
        _normalize_proposal,
    )

    item = function(tmp_path, "subscribe", "a", {"name": "heap_root", "usr": "root:heap"})
    item = (*item[:4], "void (void (*)(void))")
    item[2]["functions"][0]["parameters"] = [{"name": "notify", "type": "void (*)(void)"}]
    packet = {"_item": item, "signature": item[4]}
    value = {
        "role": "callback_register",
        "object": "notify",
        "guard": "true",
        "strength": "must_under_guard",
    }
    with pytest.raises(ValueError, match="includes NULL"):
        _check_object_type(_normalize_proposal(value, packet), packet)
    value["guard"] = "notify != NULL"
    _check_object_type(_normalize_proposal(value, packet), packet)
    value.update(guard="true", strength="may")
    _check_object_type(_normalize_proposal(value, packet), packet)


def test_identical_guard_must_subsumes_may_but_not_other_guards(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _partition_proposals

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    must = contract(packet)
    may = {**must, "strength": "may"}
    rows, rejected = _partition_proposals([may, must], packet, tmp_path)
    assert len(rows) == 1 and not rejected
    assert rows[0]["effects"][0]["strength"] == "must_under_guard"
    other = {**may, "when": {"op": "true"}, "no_effect_when": {"op": "unknown"}}
    rows, rejected = _partition_proposals([other, must], packet, tmp_path)
    assert len(rows) == 2 and not rejected


def test_rebound_pointee_check_preserves_old_generation_paths():
    from zscope.orchestration.primitive_boundary_evidence import copy_boundary_gap

    store = {"event_kind": "call", "object": {"expression": "*out"}, "block": 2, "ordinal": 0}
    write = {"event_kind": "call", "arguments": ["*out", "data"], "block": 1, "ordinal": 0}
    body = {
        "complete": True,
        "cfg_entry": 3,
        "cfg_edges": [{"from": 3, "to": 2}, {"from": 2, "to": 1}],
        "events": [store, write],
    }
    assert "rebound" in copy_boundary_gap(body, "*out")
    body["parameters"] = [{"name": "out", "usr": "param:out"}]
    body["events"].append({"defs": [{"expression": "out", "usr": "local:out"}]})
    assert not copy_boundary_gap(body, "*out")
    body["events"].pop()
    store["arguments"] = ["record->out_size"]
    assert "rebound" in copy_boundary_gap(body, "*out")
    body["complete"] = False
    assert not copy_boundary_gap(body, "*out")
    body["complete"] = True
    store["arguments"] = ["*out"]
    assert not copy_boundary_gap(body, "*out")
    store.pop("arguments")
    body["events"].insert(0, {**write, "block": 3})
    assert copy_boundary_gap(body, "*out") == ""
    body["events"].pop(0)
    body["cfg_edges"].append({"from": 3, "to": 1})
    assert copy_boundary_gap(body, "*out") == ""


def test_member_bookkeeping_filter_keeps_buffer_calls_and_output_parameters():
    from zscope.orchestration.primitive_boundary_evidence import copy_boundary_gap

    body = {
        "complete": True,
        "events": [
            {
                "event_kind": "assignment",
                "assignment_target": "item->state",
                "defs": [{"value_kind": "field"}],
            }
        ],
    }
    assert "bookkeeping" in copy_boundary_gap(body, "item->state")
    assert not copy_boundary_gap(body, "out_count")
    body["events"].append({"event_kind": "call", "arguments": ["&item->state"]})
    assert not copy_boundary_gap(body, "item->state")


def test_may_spelling_normalization_never_promotes_strength(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _normalize_proposal

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    value["strength"] = "may_under_guard"
    assert _normalize_proposal(value, packet)["strength"] == "may"
    assert value["strength"] == "may_under_guard"


def test_native_scalar_member_is_not_a_buffer_but_pointer_field_is(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _check_object_type

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    body = packet["_item"][2]["functions"][0]
    body["parameters"] = [{"name": "record", "type": "struct Record *"}]
    field = {"expression": "record->value", "value_kind": "field", "integer_bits": 32}
    body["events"] = [{"defs": [field]}]
    value = {"role": "copy", "carrier": {"root": "argument", "index": 0, "members": ["value"]}}
    with pytest.raises(ValueError, match="scalar value"):
        _check_object_type(value, packet)
    field["integer_bits"] = 0
    _check_object_type(value, packet)


def test_member_copy_requires_memory_mechanism_not_scalar_state_updates(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    body = packet["_item"][2]["functions"][0]
    body.update(
        complete=True,
        parameters=[{"name": "record", "type": "struct Record *"}],
        events=[{"event_kind": "assignment", "assignment_target": "local->state"}],
    )
    value = {
        "role": "copy",
        "object": "record->items",
        "guard": "true",
        "else": "unknown",
        "strength": "may",
        "evidence_refs": [packet["nodes"][0]["id"]],
    }
    with pytest.raises(ValueError, match="no buffer operation"):
        _proposal_rows([value], packet, tmp_path)
    body["events"].append({"event_kind": "assignment", "assignment_target": "cursor[i]"})
    assert _proposal_rows([value], packet, tmp_path)
    body["events"].pop()
    body["complete"] = False
    assert _proposal_rows([value], packet, tmp_path)


def test_filtered_bookkeeping_is_audited_separately_from_invalid_proposals(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _partition_proposals

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    body = packet["_item"][2]["functions"][0]
    body.update(
        complete=True,
        parameters=[{"name": "record", "type": "struct Record *"}],
        events=[{"event_kind": "assignment", "assignment_target": "local->state"}],
    )
    value = {
        "role": "copy",
        "object": "record->items",
        "guard": "true",
        "else": "unknown",
        "strength": "may",
        "evidence_refs": [packet["nodes"][0]["id"]],
    }
    rows, rejected = _partition_proposals([value], packet, tmp_path)
    assert not rows and not rejected
    assert packet["_filtered_proposals"][0]["contract"] == value
    invalid = {**value, "object": "invented"}
    rows, rejected = _partition_proposals([invalid], packet, tmp_path)
    assert rejected and not packet["_filtered_proposals"]


class Root:
    effects_trusted = True
    source = "builtin_defaults"
    symbol = SimpleNamespace(name="heap_root", usr="root:heap")

    def to_dict(self):
        return {
            "symbol": {"name": "heap_root"},
            "role": "allocator",
            "carrier": {"kind": "return"},
            "pairs": [{"name": "heap_dispose"}],
            "resource_family": "malloc",
            "protocol": {},
        }


def function(tmp_path, name, build, callee, *, source=None):
    path = tmp_path / (name + ".c")
    code = source or f"void *{name}(int n) {{ return {callee['name']}(n); }}"
    path.write_text(code)
    scope = InstanceScope(
        build_context_id=build,
        usr="usr:" + name,
        identity=build + ":usr:" + name,
        source=str(path),
        function_names=(name,),
    )
    return (
        scope,
        {"code": code, "file": str(path)},
        {
            "functions": [
                {
                    "parameters": [{"name": "n"}],
                    "events": [{"event_kind": "call", "callee": callee, "arguments": ["n"]}],
                }
            ]
        },
        name,
        "void *(int)",
    )


def setup(tmp_path):
    allocate = function(tmp_path, "make_item", "a", {"name": "heap_root", "usr": "root:heap"})
    forward = function(tmp_path, "forward_item", "b", {"name": "make_item", "usr": "usr:make_item"})
    return {"a": [allocate], "b": [forward]}, {"a": [Root()], "b": [Root()]}


def contract(packet):
    return {
        "role": "allocator",
        "carrier": {"root": "return", "phase": "post"},
        "strength": "must_under_guard",
        "resource_family": "malloc",
        "protocol": {},
        "when": {
            "op": "compare",
            "left": {"kind": "return"},
            "operator": "!=",
            "right": {"kind": "literal", "value": None},
        },
        "no_effect_when": {
            "op": "compare",
            "left": {"kind": "return"},
            "operator": "==",
            "right": {"kind": "literal", "value": None},
        },
        "pairs": ["builtin:heap_dispose"],
        "evidence_refs": [packet["nodes"][-1]["id"]],
        "rationale": "Returned allocation through current resolved call.",
    }


def test_planner_requires_real_link_group_and_callee_usr(tmp_path):
    work, roots = setup(tmp_path)
    packets, diagnostics = proposal_packets(
        work, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert [p["name"] for p in packets] == ["make_item"]
    assert any(
        d["name"] == "forward_item" and d["status"] == "no_resolved_root_path" for d in diagnostics
    )
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[["a", "b"]], existing=[], root=tmp_path
    )
    assert {p["name"] for p in packets} == {"make_item", "forward_item"}
    assert len(next(p for p in packets if p["name"] == "forward_item")["nodes"]) == 2
    work["b"][0][2]["functions"][0]["events"][0]["callee"]["usr"] = "different"
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[["a", "b"]], existing=[], root=tmp_path
    )
    assert [p["name"] for p in packets] == ["make_item"]


def test_primitive_roles_require_actual_mechanisms(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    body = packet["_item"][2]["functions"][0]
    body.update(complete=True, parameters=[{"name": "input", "type": "void *"}])
    packet["nodes"][0]["parameters"] = body["parameters"]
    value = {
        "object": "input",
        "role": "lock",
        "guard": "true",
        "else": "unknown",
        "strength": "may",
        "evidence_refs": [packet["id"]],
        "resource_family": "mutex",
        "pairs": [],
    }
    packet["nodes"][0]["root_contracts"] = [{"symbol": {"name": "init"}, "role": "lock_init"}]
    with pytest.raises(ValueError, match="resolved lock root"):
        _proposal_rows([value], packet, tmp_path)
    packet["nodes"][0]["root_contracts"][0]["role"] = "lock"
    assert _proposal_rows([value], packet, tmp_path)
    value.update(role="format_sink", resource_family="")
    packet["nodes"][0]["boundary_observations"] = [{"format_operand": '"value: %s"'}]
    with pytest.raises(ValueError, match="format operands are literals"):
        _proposal_rows([value], packet, tmp_path)
    packet["nodes"][0]["boundary_observations"][0]["format_operand"] = "input"
    assert _proposal_rows([value], packet, tmp_path)


def test_local_reads_are_filtered_but_system_operations_are_preserved(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _partition_proposals

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = {
        "object": "n",
        "role": "standard_operation",
        "guard": "true",
        "else": "unknown",
        "strength": "may",
        "evidence_refs": [packet["id"]],
    }
    packet["nodes"][0]["root_contracts"] = [
        {"symbol": {"name": "strchr"}, "role": "standard_operation"}
    ]
    rows, errors = _partition_proposals([value], packet, tmp_path)
    assert not rows and not errors and packet["_filtered_proposals"]
    packet["nodes"][0]["root_contracts"][0]["symbol"]["name"] = "fcntl"
    assert _proposal_rows([value], packet, tmp_path)


def test_callback_invocation_does_not_register_but_store_can(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    body = packet["_item"][2]["functions"][0]
    body.update(complete=True, parameters=[{"name": "notify", "type": "void (*)(void)"}])
    packet["nodes"][0]["parameters"] = body["parameters"]
    value = {
        "object": "notify",
        "role": "callback_register",
        "guard": "notify != NULL",
        "else": "unknown",
        "strength": "may",
        "evidence_refs": [packet["id"]],
    }
    with pytest.raises(ValueError, match="only callback invocation"):
        _proposal_rows([value], packet, tmp_path)
    body["events"].append(
        {"event_kind": "assignment", "assignment_value": "notify", "assignment_target": "slot"}
    )
    assert _proposal_rows([value], packet, tmp_path)


def test_discarded_close_result_does_not_guarantee_release(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    packet["nodes"][0]["root_contracts"] = [{"symbol": {"name": "close"}, "role": "io_release"}]
    body = packet["_item"][2]["functions"][0]
    body["events"] = [{"event_kind": "call", "callee": {"name": "close"}, "arguments": ["n"]}]
    value = {
        "object": "n",
        "role": "io_release",
        "guard": "true",
        "else": "unknown",
        "strength": "must_under_guard",
        "evidence_refs": [packet["id"]],
        "resource_family": "descriptor",
    }
    with pytest.raises(ValueError, match="results are discarded"):
        _proposal_rows([value], packet, tmp_path)
    value["strength"] = "may"
    assert _proposal_rows([value], packet, tmp_path)
    value["strength"] = "must_under_guard"
    body["events"].append({"event_kind": "return", "return_value": "close(n)"})
    assert _proposal_rows([value], packet, tmp_path)


def test_discarded_release_in_exact_callee_is_not_target_success(tmp_path):
    work, roots = setup(tmp_path)
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[["a", "b"]], existing=[], root=tmp_path
    )
    packet = next(p for p in packets if p["name"] == "forward_item")
    callee = next(n for n in packet["nodes"] if n["id"] != packet["id"])
    callee["root_contracts"] = [{"symbol": {"name": "close"}, "role": "io_release"}]
    body = packet["_native_by_node"][callee["id"]]
    body["events"] = [{"event_kind": "call", "callee": {"name": "close"}, "arguments": ["n"]}]
    value = {
        "object": "n",
        "role": "io_release",
        "guard": "true",
        "else": "unknown",
        "strength": "must_under_guard",
        "resource_family": "descriptor",
        "evidence_refs": [packet["id"], callee["id"]],
    }
    with pytest.raises(ValueError, match="results are discarded"):
        _proposal_rows([value], packet, tmp_path)
    # Propagated status and missing exact callee evidence need semantic review.
    body["events"][0]["defs"] = [{"usr": "status", "expression": "status"}]
    assert _proposal_rows([value], packet, tmp_path)
    body["events"][0].pop("defs")
    packet["_native_by_node"].pop(callee["id"])
    assert _proposal_rows([value], packet, tmp_path)


def test_shadowed_root_and_ambiguous_variants_cannot_supply_evidence(tmp_path):
    work, roots = setup(tmp_path)
    work["a"][0][2]["functions"][0]["events"][0]["callee"].update(
        has_definition=True, is_system_header=False
    )
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[["a", "b"]], existing=[], root=tmp_path
    )
    assert packets == []


@pytest.mark.parametrize(
    "mutation", ["evidence", "argument", "unknown", "pair", "overlap", "member", "extent", "offset"]
)
def test_proposals_reject_unbound_or_unconfirmable_output(tmp_path, mutation):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    if mutation == "evidence":
        value["evidence_refs"] = ["invented"]
    elif mutation == "argument":
        value["carrier"] = {"root": "argument", "index": 99}
    elif mutation == "unknown":
        value["when"] = {"op": "unknown"}
    elif mutation == "pair":
        value["pairs"] = ["builtin:unrelated_release"]
    elif mutation == "overlap":
        value["when"] = {"op": "true"}
    elif mutation == "member":
        value["carrier"]["members"] = ["->member"]
    elif mutation == "extent":
        value["protocol"] = {"allocation_extent": [{"kind": "literal", "value": "sizeof(Node)"}]}
    else:
        packet["_item"][2]["functions"][0]["events"].append(
            {"event_kind": "return", "return_value": "raw + 16u"}
        )
    with pytest.raises(ValueError):
        _proposal_rows([value], packet, tmp_path)


def test_model_proposes_new_effects_and_repairs_without_confirming(tmp_path):
    work, roots = setup(tmp_path)

    class Model:
        calls = 0

        def chat_completion(self, messages, **kwargs):
            self.calls += 1
            # Simple complete evidence gets a cheap counterexample review;
            # it still receives the second semantic decision.
            assert kwargs["thinking"]["type"] == "disabled"
            packet = json.loads(messages[1]["content"])
            value = contract(packet)
            if self.calls == 1:
                value["when"] = {"op": "unknown"}
            return {"choices": [{"message": {"content": json.dumps({"contracts": [value]})}}]}

    model = Model()
    rows, audit = propose_contracts(
        model, work={"a": work["a"]}, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert model.calls == 2
    assert audit["reviewed"] == 1 and not audit["errors"]
    assert len(rows) == 1 and rows[0]["status"] == "pending"
    assert rows[0]["variants"][0]["build_context_id"] == "a"
    assert rows[0]["proposal_origin"] == "llm_source_composition"


def test_exact_duplicates_do_not_retry_but_different_meanings_are_preserved(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _partition_proposals

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    different = deepcopy(value)
    different["strength"] = "may"
    different["when"] = {"op": "true"}
    different["no_effect_when"] = {"op": "unknown"}
    rows, rejected = _partition_proposals([value, deepcopy(value), different], packet, tmp_path)
    assert not rejected
    assert len(rows) == 2
    assert {r["effects"][0]["strength"] for r in rows} == {"may", "must_under_guard"}
    invalid = deepcopy(value)
    invalid["evidence_refs"] = ["unrelated"]
    assert _partition_proposals([value, invalid], packet, tmp_path)[1]


def test_callback_diagnostic_points_to_value_not_storage_container(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _check_object_type

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    body = packet["_item"][2]["functions"][0]
    body["parameters"] = [
        {"name": "store", "type": "struct Store *"},
        {"name": "on_event", "type": "void (*)(int)"},
        {"name": "data", "type": "void *"},
    ]
    value = {
        "role": "callback_register",
        "carrier": {"root": "argument", "index": 0, "members": ["slots"]},
    }
    with pytest.raises(ValueError, match="on_event"):
        _check_object_type(value, packet)
    value["carrier"] = {"root": "argument", "index": 1}
    _check_object_type(value, packet)
    value["carrier"]["index"] = 2
    with pytest.raises(ValueError, match="NOT the container"):
        _check_object_type(value, packet)


def test_identity_review_hints_are_scoped_to_emitted_roles_and_rejected_callbacks():
    from zscope.orchestration.primitive_contract_proposals import _identity_review_hints

    copy_hint = _identity_review_hints({"x": ([{"effects": [{"role": "copy"}]}], "", [])})
    assert "pointer SLOT" in copy_hint and "FUNCTION POINTER" not in copy_hint
    hint = _identity_review_hints({"x": ([{"effects": [{"role": "lock"}]}], "", [])})
    assert "unmatched responsibility" in hint and "FUNCTION POINTER" not in hint
    hint = _identity_review_hints({"x": ([], "", [{"error": "callback_register invalid object"}])})
    assert "FUNCTION POINTER" in hint and "unmatched responsibility" not in hint


def test_variant_propositions_do_not_share_a_row_id(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    first = contract(packet)
    second = deepcopy(first)
    second["strength"] = "may"
    a = _proposal_rows([first], packet, tmp_path)[0]
    b = _proposal_rows([second], packet, tmp_path)[0]
    assert a["id"] != b["id"]
    b["id"] = a["id"]
    b["variants"][0]["build_context_id"] = "other"
    merged = _merge_variants([a, b])
    assert len(merged) == 2
    assert all(len(row["variants"]) == 1 for row in merged)


def test_partial_output_retains_valid_effect_and_unreplaced_native_draft(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    original = contract(packet)
    original["strength"] = "may"
    prior = _proposal_rows([original], packet, tmp_path)[0]
    prior.pop("proposal_origin")
    prior["id"] = "native-allocation-draft"
    release = deepcopy(prior)
    release["id"] = "native-independent-release"
    release["effects"][0].update(role="deallocator", operation="deallocator")
    release["effects"][0]["carrier"] = {"root": "argument", "index": 0, "phase": "pre"}

    class Model:
        calls = 0

        def chat_completion(self, messages, **kwargs):
            self.calls += 1
            if self.calls == 2:
                # The repair sees the actual rejected output, not just a
                # disconnected validation error.
                assert messages[-2]["role"] == "assistant"
                assert '"index": 1' in messages[-1]["content"]
            value = contract(json.loads(messages[1]["content"]))
            invalid = deepcopy(value)
            invalid["carrier"] = {"root": "argument", "index": 1234}
            return {
                "choices": [{"message": {"content": json.dumps({"contracts": [value, invalid]})}}]
            }

    rows, audit = propose_contracts(
        Model(),
        work={"a": work["a"]},
        roots=roots,
        link_groups=[],
        existing=[prior, release],
        root=tmp_path,
    )
    assert len(rows) == 2
    assert {r["id"] for r in rows} >= {"native-independent-release"}
    assert "native-allocation-draft" not in {r["id"] for r in rows}
    assert audit["reviewed"] == 0 and len(audit["errors"]) == 1
    unit = next(u for u in audit["units"] if u["name"] == "make_item")
    assert unit["status"] == "partial"
    assert unit["rejected_contracts"][0]["index"] == 1
    assert all(row["status"] == "pending" for row in rows)


def test_truncated_review_preserves_draft_and_specific_correction(tmp_path):
    work, roots = setup(tmp_path)

    class Model:
        calls = 0

        def chat_completion(self, messages, **kwargs):
            self.calls += 1
            value = contract(json.loads(messages[1]["content"]))
            if self.calls == 1:
                value["carrier"] = {"root": "argument", "index": 1234}
            elif self.calls == 2:
                return {
                    "choices": [
                        {
                            "finish_reason": "length",
                            "message": {"content": "partial untrusted draft"},
                        }
                    ]
                }
            else:
                assert len(messages) == 4
                assert messages[-2]["role"] == "assistant"
                assert "1234" in messages[-2]["content"]
                assert "carrier argument out of range" in messages[-1]["content"]
                assert "truncated response" in messages[-1]["content"]
                assert "partial untrusted draft" not in str(messages)
            return {"choices": [{"message": {"content": json.dumps({"contracts": [value]})}}]}

    rows, audit = propose_contracts(
        Model(), work={"a": work["a"]}, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert len(rows) == 1 and audit["reviewed"] == 1 and not audit["errors"]


def test_input_output_phases_and_nested_macro_operand_substitution():
    assert _object_path({"kind": "argument", "argument_index": 1})["phase"] == "pre"
    assert _object_path({"kind": "output_argument", "argument_index": 1})["phase"] == "post"
    assert _macro_arguments("copy_it(dst, src, sizeof(dst))", "copy_it") == [
        "dst",
        "src",
        "sizeof(dst)",
    ]
    predicate = {
        "op": "compare",
        "left": {"kind": "argument", "index": 0},
        "operator": ">=",
        "right": {"kind": "global", "name": "threshold"},
    }
    mapped = _remap_macro_value(
        predicate,
        body="emit(INFO, fmt)",
        callee_name="emit",
        parameters=["fmt"],
        constants={"INFO": 2},
    )
    assert mapped["left"] == {"kind": "literal", "value": 2}
    assert mapped["right"] == predicate["right"]


def test_macro_predicate_preserves_address_identity_not_mutex_value():
    from zscope.semantics.contract_conditions import evaluate

    condition = {
        "op": "compare",
        "left": {"kind": "argument", "argument_index": 0},
        "operator": "!=",
        "right": {"kind": "literal", "value": None},
    }
    mapped = _remap_macro_value(
        condition, body="release(&module_lock)", callee_name="release", parameters=[], constants={}
    )
    assert mapped["left"]["address_of"] is True
    assert evaluate(mapped, facts={"module_lock": None}) == "unknown"
    assert evaluate(mapped, facts={"&module_lock": 123}) == "applies"
    swapped = _remap_macro_value(
        condition,
        body="release(second)",
        callee_name="release",
        parameters=["first", "second"],
        constants={},
    )
    assert swapped["left"] == {"kind": "argument", "index": 1}


def test_large_source_is_not_silently_truncated(tmp_path):
    work, roots = setup(tmp_path)
    item = work["a"][0]
    item[1]["code"] = "x" * 21000
    packets, diagnostic = proposal_packets(
        work, roots=roots, link_groups=[], existing=[], root=tmp_path
    )
    assert not packets
    assert any(d["status"] == "packet_budget_exceeded" for d in diagnostic)


def test_replacing_one_variant_retains_other_native_draft(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    value["strength"] = "may"
    prior = _proposal_rows([value], packet, tmp_path)[0]
    prior["id"] = "shared-native-draft"
    prior["variants"].append({**prior["variants"][0], "build_context_id": "unreviewed-variant"})

    class Model:
        def chat_completion(self, messages, **kwargs):
            value = contract(json.loads(messages[1]["content"]))
            return {"choices": [{"message": {"content": json.dumps({"contracts": [value]})}}]}

    rows, _ = propose_contracts(
        Model(), work={"a": work["a"]}, roots=roots, link_groups=[], existing=[prior], root=tmp_path
    )
    native = next(row for row in rows if row["id"] == "shared-native-draft")
    assert [v["build_context_id"] for v in native["variants"]] == ["unreviewed-variant"]


def test_named_objects_and_compact_guards_keep_target_indices_and_member_exclusions(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    value.pop("carrier")
    value.pop("when")
    value.pop("no_effect_when")
    value.update(
        object="return->payload",
        guard="return != NULL && return->payload != NULL",
        **{"else": "no_effect"},
    )
    row = _proposal_rows([value], packet, tmp_path)[0]
    assert row["effects"][0]["carrier"]["members"] == ["payload"]
    assert row["effects"][0]["carrier"]["dereference"] == 0
    assert row["cases"][1]["effect"] == "no_effect"
    assert row["cases"][0]["when"]["items"][1]["left"]["member_path"] == "->payload"
    value["object"] = "callee_parameter"
    with pytest.raises(ValueError, match="target parameter"):
        _proposal_rows([value], packet, tmp_path)


def test_void_target_cannot_borrow_a_callee_result_in_either_guard(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    packet["signature"] = "void (int)"
    public = _public_batch([packet])["targets"][0]
    assert public["return_type"] == "void"
    assert "return" not in public["boundary_objects"]
    value = contract(packet)
    value.update(object="n", role="standard_operation", pairs=[])
    with pytest.raises(ValueError, match="target returns void"):
        _proposal_rows([value], packet, tmp_path)
    value["when"] = {"op": "true"}
    with pytest.raises(ValueError, match="target returns void"):
        _proposal_rows([value], packet, tmp_path)
    value["no_effect_when"] = {"op": "unknown"}
    packet["nodes"][0]["root_contracts"].append(
        {"symbol": {"name": "descriptor_query"}, "role": "standard_operation"}
    )
    assert _proposal_rows([value], packet, tmp_path)
    packet["signature"] = "void (*(int))(int)"
    assert "return" in _public_batch([packet])["targets"][0]["boundary_objects"]


def test_variadic_marker_does_not_erase_fixed_parameter_types(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _parameters

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    packet["_item"][2]["functions"][0]["callable"] = {"canonical_signature": "void (int, ...)"}
    assert _parameters(packet["_item"])[0]["type"] == "int"


def test_unrepresentable_macro_guard_requests_equivalent_observable_condition(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _macro_guard_gaps

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    packet["macro_consumers"] = [{"definition": "#define SIZED(x) make_item(sizeof(x))"}]
    value = contract(packet)
    value.update(guard="n > 0", **{"else": "unknown"})
    rows = _proposal_rows([value], packet, tmp_path)
    assert _macro_guard_gaps(packet, rows)
    value["guard"] = "return != NULL"
    assert not _macro_guard_gaps(packet, _proposal_rows([value], packet, tmp_path))
    packet["macro_consumers"] = [{"definition": "#define CHANGED(x) make_item(sizeof(x)) + 1"}]
    assert not _macro_guard_gaps(packet, rows)


def test_missing_exclusion_is_unknown_not_a_fabricated_negative_or_lost_positive(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    value.pop("no_effect_when")
    row = _proposal_rows([value], packet, tmp_path)[0]
    assert len(row["cases"]) == 1
    assert row["otherwise"] == "unknown" and row["status"] == "pending"


@pytest.mark.parametrize(
    "mutation", ["status", "descriptor", "const_destination", "member_indirection"]
)
def test_native_type_contradictions_do_not_become_confirmable_proposals(tmp_path, mutation):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    if mutation == "status":
        packet["signature"] = "int (int)"
    else:
        param = packet["_item"][2]["functions"][0]["parameters"][0]
        param["type"] = {
            "descriptor": "int",
            "const_destination": "const char *",
            "member_indirection": "struct Owner *",
        }[mutation]
        value.update(role="copy", resource_family="", pairs=[])
        value["carrier"] = {"root": "argument", "index": 0, "phase": "pre"}
        if mutation == "member_indirection":
            value["carrier"].update(dereference=1, members=["payload"])
    with pytest.raises(ValueError):
        _proposal_rows([value], packet, tmp_path)


def test_batches_share_evidence_without_shrinking_target_scope(tmp_path):
    work, roots = setup(tmp_path)
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[["a", "b"]], existing=[], root=tmp_path
    )
    batches = _proposal_batches(packets)
    assert len(batches) == len(packets)
    assert all(len(batch) == 1 for batch in batches)
    public = _public_batch(packets)
    assert {t["id"] for t in public["targets"]} == {p["id"] for p in packets}
    assert len(public["nodes"]) == 2
    assert len(public["roots"]) == 1
    # The caller can cite both nodes; the callee cannot cite the unrelated caller.
    value = contract(packets[0])
    own = next(p for p in packets if p["name"] == "make_item")
    caller = next(p for p in packets if p["name"] == "forward_item")
    value["evidence_refs"] = [caller["id"]]
    with pytest.raises(ValueError, match="evidence_refs"):
        _proposal_rows([value], own, tmp_path)


def test_native_abi_parameters_and_root_citations(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _parameters

    work, roots = setup(tmp_path)
    item = work["a"][0]
    assert _parameters(item)[0]["type"] == "int"
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    root_id = next(iter(_public_batch([packet])["roots"]))
    value["evidence_refs"].append(root_id)
    assert _proposal_rows([value], packet, tmp_path)
    value["evidence_refs"] = [root_id]
    with pytest.raises(ValueError, match="source node"):
        _proposal_rows([value], packet, tmp_path)


def test_missing_batch_target_preserves_independent_result(tmp_path):
    work, roots = setup(tmp_path)
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[["a", "b"]], existing=[], root=tmp_path
    )
    chosen = packets[0]

    class Client:
        def chat_completion(self, *args, **kwargs):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {"results": [{"id": chosen["id"], "contracts": [contract(chosen)]}]}
                            )
                        }
                    }
                ]
            }

    rows, audit = propose_contracts(
        Client(), work=work, roots=roots, link_groups=[["a", "b"]], existing=[], root=tmp_path
    )
    assert len(rows) == 1
    assert audit["reviewed"] == 1
    assert len(audit["errors"]) == 1


def test_macro_keeps_independent_mappable_effect_and_exact_build(tmp_path):
    from zscope.orchestration.primitive_discovery import _macro_candidates

    (tmp_path / "api.h").write_text("#define OUTPUT(msg) emit(17, msg)\n")
    selector = {
        "kind": "function",
        "name": "emit",
        "file": "api.c",
        "usr": "usr:emit",
        "signature": "void(int, const char*)",
    }

    def row(index):
        return {
            "id": "effect:" + str(index),
            "selector": selector,
            "effects": [
                {
                    "role": "format_sink",
                    "domain": "taint",
                    "carrier": {"root": "argument", "index": index},
                }
            ],
            "cases": [{"when": {"op": "true"}, "effect": "applies"}],
            "pairs": [],
            "variants": [{"build_context_id": "a"}],
        }

    bindings = {
        ("OUTPUT", "api.h", 1): [
            {"usr": "macro:OUTPUT", "build_context_id": "a"},
            {"usr": "macro:OUTPUT", "build_context_id": "b"},
        ]
    }
    output = _macro_candidates(
        root=tmp_path, bindings=bindings, interfaces=[row(0), row(1)], roots={}
    )
    assert len(output) == 1
    assert output[0]["effects"][0]["carrier"]["index"] == 0
    assert [v["build_context_id"] for v in output[0]["variants"]] == ["a"]
    assert output[0]["derived_from"] == ["effect:1"]


def test_macro_consumer_context_only_from_current_build(tmp_path):
    work, roots = setup(tmp_path)
    (tmp_path / "api.h").write_text("#define FORWARD(x) make_item(sizeof(x))\n")
    bindings = {("FORWARD", "api.h", 1): [{"usr": "macro:FORWARD", "build_context_id": "a"}]}
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[], existing=[], root=tmp_path, macro_bindings=bindings
    )
    assert packets[0]["macro_consumers"][0]["arguments"] == ["sizeof(x)"]
    bindings[("FORWARD", "api.h", 1)][0]["build_context_id"] = "other"
    packets, _ = proposal_packets(
        work, roots=roots, link_groups=[], existing=[], root=tmp_path, macro_bindings=bindings
    )
    assert packets[0]["macro_consumers"] == []


def test_cross_tu_macro_requires_link_membership_and_exact_callee_reference(tmp_path):
    from zscope.orchestration.primitive_discovery import _macro_candidates

    work, roots = setup(tmp_path)
    packets, _ = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)
    row = _proposal_rows([contract(packets[0])], packets[0], tmp_path)[0]
    (tmp_path / "api.h").write_text("#define ALLOCATE(x) make_item(x)\n")
    bindings = {("ALLOCATE", "api.h", 1): [{"usr": "macro:ALLOCATE", "build_context_id": "b"}]}
    args = dict(root=tmp_path, bindings=bindings, interfaces=[row], roots={}, work=work)
    assert not _macro_candidates(**args)
    linked = _macro_candidates(**args, link_groups=[["a", "b"]])
    assert len(linked) == 1 and linked[0]["variants"][0]["build_context_id"] == "b"
    variants = row.pop("variants")
    assert not _macro_candidates(**args, link_groups=[["a", "b"]])
    row["variants"] = variants
    work["b"][0][2]["functions"][0]["events"][0]["callee"]["usr"] = "different:make_item"
    assert not _macro_candidates(**args, link_groups=[["a", "b"]])


def test_cross_tu_macro_does_not_choose_between_two_linked_definitions(tmp_path):
    from zscope.orchestration.primitive_discovery import _macro_candidates

    work, roots = setup(tmp_path)
    packets, _ = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)
    row = _proposal_rows([contract(packets[0])], packets[0], tmp_path)[0]
    work["c"] = [function(tmp_path, "make_item", "c", {"name": "heap_root", "usr": "root:heap"})]
    (tmp_path / "api.h").write_text("#define ALLOCATE(x) make_item(x)\n")
    bindings = {("ALLOCATE", "api.h", 1): [{"usr": "macro:ALLOCATE", "build_context_id": "b"}]}
    assert not _macro_candidates(
        root=tmp_path,
        bindings=bindings,
        interfaces=[row],
        roots={},
        work=work,
        link_groups=[["a", "b", "c"]],
    )


def test_native_offset_counterevidence_rejects_even_may_clause(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    packet["_item"][2]["functions"][0]["parameters"][0]["type"] = "char *"
    packet["object_constraints"] = [{"argument_index": 0, "role": "deallocator"}]
    value = contract(packet)
    value.update(role="deallocator", object="n", strength="may", pairs=[])
    with pytest.raises(ValueError, match="native offset"):
        _proposal_rows([value], packet, tmp_path)


def test_reasoning_review_is_reserved_for_composition_without_skipping_review(tmp_path):
    from zscope.orchestration.primitive_contract_proposals import _deep_counterexample_review

    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    assert not _deep_counterexample_review(packet, {})
    packet["incomplete_evidence"] = ["callee_depth_bound:some_node"]
    assert _deep_counterexample_review(packet, {})
    row = _proposal_rows([contract(packet)], packet, tmp_path)[0]
    assert _deep_counterexample_review(packet, {packet["id"]: ([row], "", [])})
    row["effects"][0]["strength"] = "may"
    row["cases"] = [{"when": {"op": "true"}, "effect": "applies"}]
    # A weak claim still needs reasoning when its supporting call graph is incomplete.
    assert _deep_counterexample_review(packet, {packet["id"]: ([row], "", [])})
    row["cases"].append(
        {
            "when": {
                "op": "compare",
                "left": {"kind": "return"},
                "operator": "==",
                "right": {"kind": "literal", "value": None},
            },
            "effect": "no_effect",
        }
    )
    assert _deep_counterexample_review(packet, {packet["id"]: ([row], "", [])})
    packet["incomplete_evidence"] = []
    # Even a small wrapper needs reasoning for a result-dependent exclusion:
    # a failure return can follow partial writes or an unsigned length conversion.
    assert _deep_counterexample_review(packet, {packet["id"]: ([row], "", [])})
    packet["object_constraints"] = [{"role": "copy", "argument_index": 0}]
    assert _deep_counterexample_review(packet, {})


def test_receive_requires_real_root_not_input_buffer_name(tmp_path):
    work, roots = setup(tmp_path)
    packet = proposal_packets(work, roots=roots, link_groups=[], existing=[], root=tmp_path)[0][0]
    value = contract(packet)
    value.update(role="recv_source", pairs=[], resource_family="")
    with pytest.raises(ValueError, match="receive-source root"):
        _proposal_rows([value], packet, tmp_path)
    # The same output flow is admissible when the target has a real receive
    # root; this is evidence admissibility, not proof of the proposed alias.
    packet["nodes"][0]["root_contracts"].append(
        {
            "symbol": {"name": "input_root", "usr": "root:input"},
            "role": "recv_source",
            "pairs": [],
        }
    )
    assert _proposal_rows([value], packet, tmp_path)[0]["effects"][0]["role"] == "recv_source"
