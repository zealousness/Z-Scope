from zscope.orchestration.primitive_object_evidence import offset_conflicts


def symbol(name, *, scalar=False):
    return {"usr": "usr:" + name, "expression": name, "integer_bits": 32 if scalar else 0}


def root(role):
    return {
        "symbol": {"name": "primitive", "usr": "usr:primitive"},
        "role": role,
        "carrier": {"kind": "argument", "argument_index": 0},
    }


def call(expression, used):
    return {
        "event_kind": "call",
        "callee": {"name": "primitive", "usr": "usr:primitive"},
        "arguments": [expression],
        "argument_uses": [used],
        "event_id": "1:0",
    }


def test_displaced_release_cannot_be_confirmed_as_base_release():
    body = {"parameters": [symbol("owned")], "events": [call("owned + 1", [symbol("owned")])]}
    assert offset_conflicts(body, [root("deallocator")])[0]["argument_index"] == 0
    body["events"] = [call("owned", [symbol("owned")])]
    assert not offset_conflicts(body, [root("deallocator")])


def test_backward_copy_tracks_native_local_identities_not_just_argument_spelling():
    body = {
        "parameters": [symbol("buffer"), symbol("count", scalar=True)],
        "events": [
            {
                "assignment_value": "buffer + 8",
                "defs": [symbol("cursor")],
                "uses": [symbol("buffer")],
            },
            {
                "assignment_value": "cursor - count",
                "defs": [symbol("destination")],
                "uses": [symbol("cursor"), symbol("count", scalar=True)],
            },
            call("destination", [symbol("destination")]),
        ],
    }
    assert [r["argument_index"] for r in offset_conflicts(body, [root("copy")])] == [0]
    # Length arithmetic must not contaminate the destination's identity.
    body["events"][-1] = call("buffer", [symbol("buffer")])
    assert not offset_conflicts(body, [root("copy")])


def test_independent_exact_destination_is_not_rejected_with_offset_site():
    body = {
        "parameters": [symbol("out")],
        "events": [call("out - 2", [symbol("out")]), call("out", [symbol("out")])],
    }
    assert not offset_conflicts(body, [root("copy")])


def test_alternative_alias_definitions_do_not_erase_a_direct_base_path():
    body = {
        "parameters": [symbol("out")],
        "events": [
            {"assignment_value": "out - 1", "defs": [symbol("alias")], "uses": [symbol("out")]},
            {"assignment_value": "out", "defs": [symbol("alias")], "uses": [symbol("out")]},
            call("alias", [symbol("alias")]),
        ],
    }
    assert not offset_conflicts(body, [root("copy")])
    assert not offset_conflicts(body, [root("deallocator")])
    body["events"][1]["assignment_value"] = "out - 2"
    assert offset_conflicts(body, [root("copy")])


def test_ordinary_forward_receive_and_same_name_nonroot_are_not_blocked():
    body = {"parameters": [symbol("out")], "events": [call("out + n", [symbol("out")])]}
    assert not offset_conflicts(body, [root("recv_source")])
    body["events"][0]["callee"]["usr"] = "other:primitive"
    assert not offset_conflicts(body, [root("deallocator")])


def test_shadowed_local_does_not_borrow_parameter_identity():
    body = {
        "parameters": [symbol("out")],
        "events": [call("out - 1", [{"usr": "shadow:out", "expression": "out"}])],
    }
    assert not offset_conflicts(body, [root("copy")])


def test_literal_zero_preserves_base_but_an_additional_offset_does_not():
    for expression in ("owned + 0", "owned - 0UL", "owned + 0x0"):
        body = {"parameters": [symbol("owned")], "events": [call(expression, [symbol("owned")])]}
        assert not offset_conflicts(body, [root("deallocator")])
    body["events"] = [call("owned + 0 + 1", [symbol("owned")])]
    assert offset_conflicts(body, [root("deallocator")])
