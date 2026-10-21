"""Real native evidence for bounded descriptor slots, not host OS behavior."""

from copy import deepcopy
import json

import pytest

from test_single_slot_pool import native_index, native_context
from zscope.semantics.handle_protocols import verify_handle_contract
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.semantics.contracts import ApiContract, ContractRegistry

HEADER = "typedef struct Table {int live0, object0, live1, object1, sequence;} Table;\n"
APIS = """
int h_open(Table *t) {
    if(t->sequence==2147483647) return -1;
    if(!t->live0) {t->sequence++; t->object0=t->sequence; t->live0=1; return 0;}
    if(!t->live1) {t->sequence++; t->object1=t->sequence; t->live1=1; return 1;}
    return -1;
}
int h_close(Table *t, int fd, int fail) {
    if(fail) return -1;
    if(fd==0 && t->live0) {t->live0=0; t->object0=0; return 0;}
    if(fd==1 && t->live1) {t->live1=0; t->object1=0; return 0;}
    return -1;
}
int h_close_late(Table *t, int fd, int fail) {
    if(fd==0 && t->live0) {t->live0=0; t->object0=0; if(fail) return -1; return 0;}
    if(fd==1 && t->live1) {t->live1=0; t->object1=0; if(fail) return -1; return 0;}
    return -1;
}
int h_dup(Table *t, int fd) {
    if(fd==0 && t->live0) {
        if(!t->live1) {t->object1=t->object0; t->live1=1; return 1;}
        return -1;
    }
    if(fd==1 && t->live1) {
        if(!t->live0) {t->object0=t->object1; t->live0=1; return 0;}
        return -1;
    }
    return -1;
}
int wrapped_close(Table *t, int fd) {return h_close(t,fd,0);}
static int (*const cleanup[1])(Table *,int,int)={h_close};
void table_close(Table *t,int fd) {cleanup[0](t,fd,0);}
Table *expired_table(void) {Table dead={0};return &dead;}
int escaped_handle(void) {Table local={0}; return h_open(&local);}
"""

SCENARIOS = {
    "zero": "if(fd>=0) h_close(&t,fd,0);",
    "truthiness": "if(fd) h_close(&t,fd,0);",
    "failed_close": "h_close(&t,fd,1);",
    "retry_preserved": "if(h_close(&t,fd,1)<0) h_close(&t,fd,0);",
    "late_error": "h_close_late(&t,fd,1);",
    "retry_consumed": "if(h_close_late(&t,fd,1)<0) h_close(&t,fd,0);",
    "dup_survives": "int copy=h_dup(&t,fd); h_close(&t,fd,0);",
    "dup_cleanup": "int copy=h_dup(&t,fd); h_close(&t,fd,0); h_close(&t,copy,0);",
    "dup_reuse": "int copy=h_dup(&t,fd); h_close(&t,fd,0); int fresh=h_dup(&t,copy); h_close(&t,fresh,0); h_close(&t,copy,0);",
    "dup_full": "int copy=h_dup(&t,fd); int failed=h_dup(&t,fd); h_close(&t,failed,0); h_close(&t,copy,0); h_close(&t,fd,0);",
    "open_full": "int second=h_open(&t); int failed=h_open(&t); h_close(&t,failed,0); h_close(&t,second,0); h_close(&t,fd,0);",
    "reopen": "h_close(&t,fd,0); int fresh=h_open(&t); h_close(&t,fresh,0);",
    "stale_close": "h_close(&t,fd,0); int fresh=h_open(&t); h_close(&t,fd,0);",
    "stale_dup": "h_close(&t,fd,0); int fresh=h_open(&t); int copy=h_dup(&t,fd); h_close(&t,copy,0); h_close(&t,fresh,0);",
    "copy_not_dup": "int alias=fd; h_close(&t,fd,0); h_close(&t,alias,0);",
    "closed_dup": "h_close(&t,fd,0); h_dup(&t,fd);",
    "wrong_table": "Table other={0}; int otherfd=h_open(&other); h_close(&other,fd,0); h_close(&t,fd,0);",
    "wrapped": "wrapped_close(&t,fd);",
    "ops": "table_close(&t,fd);",
    "unknown_identity": "h_close(&t,0,0);",
    "mutated_live": "t.live0=0; h_close(&t,fd,0);",
    "mutated_backing": "t.object0=99; h_close(&t,fd,0);",
    "sequence_reset": "h_close(&t,fd,0); t.sequence=0; h_open(&t);",
    "unsigned_copy": "unsigned copy=fd; h_close(&t,copy,0);",
    "arithmetic": "fd++; h_close(&t,fd,0);",
    "saturated": "t.sequence=2147483647; int failed=h_open(&t); h_close(&t,failed,0); h_close(&t,fd,0);",
    "expired_table": "Table *dead=expired_table(); h_open(dead);",
    "expired_block": "Table *dead=0; {Table inner={0};dead=&inner;} h_open(dead);",
    "escaped_handle": "int escaped=escaped_handle();",
}


def entry_source():
    return "\n".join(
        "void scenario_" + name + "(void) {Table t={0}; int fd=h_open(&t); " + code + "}"
        for name, code in SCENARIOS.items()
    )


def proposal(operation, failure=""):
    return {
        "role": "standard_operation",
        "carrier": (
            {"kind": "return"} if operation == "open" else {"kind": "argument", "argument_index": 1}
        ),
        "resource_domain": {"kind": "argument", "argument_index": 0},
        "protocol": {
            "kind": "bounded_handle_table",
            "operation": operation,
            "handle_slots": [
                {"value": n, "live_path": "->live" + str(n), "object_path": "->object" + str(n)}
                for n in (0, 1)
            ],
            **({"sequence_path": "->sequence"} if operation == "open" else {}),
            **({"close_failure": failure} if operation == "close" else {}),
        },
        "effect_cases": [{"when": {"op": "unknown"}, "effect": "applies"}],
        "evidence": [{"lines": "1", "description": "Source proposal without proof authority"}],
    }


def proposals():
    return {
        "h_open": proposal("open"),
        "h_close": proposal("close", "preserves"),
        "h_close_late": proposal("close", "consumes"),
        "h_dup": proposal("dup"),
    }


@pytest.fixture(scope="module")
def handle_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("handle-native")
    source = root / "handles.c"
    negatives = (
        ("int h_dup" + APIS.split("int h_dup", 1)[1].split("int wrapped_close", 1)[0])
        .replace("h_dup", "bad_dup")
        .replace("t->object1=t->object0", "t->object1=99")
    )
    source.write_text(HEADER + APIS + negatives + entry_source())
    database = root / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", str(source)],
                }
            ]
        )
    )
    backend, index = native_index(root, source, database)
    try:
        yield index, source
    finally:
        backend.close()


def registered(project):
    index, source = project
    registry = ContractRegistry()
    for name, raw in proposals().items():
        row = verify_handle_contract(raw, native_context(index, source, name))
        assert row, name
        registry.add(ApiContract.from_row({"contract": row}))
    return registry


@pytest.mark.parametrize("name", list(proposals()))
def test_actual_native_handle_contracts(handle_project, name):
    index, source = handle_project
    context = native_context(index, source, name)
    raw = proposals()[name]
    raw["evidence"][0]["lines"] = str(context["start_line"])
    snapshot = {**context, "interface_contracts": [raw]}
    compile_snapshot(snapshot, context, ContractRegistry())
    (row,) = snapshot["interface_contracts"]
    contract = ApiContract.from_row({"contract": row})
    assert contract.effects_trusted and contract.role == "standard_operation"
    assert contract.verification["checker"] == "bounded_handle_table.v1"
    assert not contract.pairs and not contract.verification["proof_authority"]


def test_close_status_is_not_the_consumption_predicate(handle_project):
    registry = registered(handle_project)
    contracts = [c for c in registry.contracts if c.symbol.name in {"h_close", "h_close_late"}]
    assert len(contracts) == 2
    assert {c.protocol["close_failure"] for c in contracts} == {"consumes", "preserves"}
    assert all(c.effect_cases[0]["when"] == {"op": "unknown"} for c in contracts)


@pytest.mark.parametrize(
    "mutation",
    [
        "false_failure",
        "wrong_role",
        "same_fields",
        "missing_receipt",
        "wrong_dup",
        "macro",
        "bitfield",
        "unsigned",
    ],
)
def test_unverified_shapes_do_not_gain_effects(handle_project, mutation):
    index, source = handle_project
    name = "bad_dup" if mutation == "wrong_dup" else "h_close"
    raw = proposal("dup") if mutation == "wrong_dup" else proposal("close", "preserves")
    context = deepcopy(native_context(index, source, name))
    if mutation == "false_failure":
        raw["protocol"]["close_failure"] = "consumes"
    if mutation == "wrong_role":
        raw["role"] = "io_release"
    if mutation == "same_fields":
        raw["protocol"]["handle_slots"][0]["object_path"] = "->live0"
    body = context["program_facts"]["functions"][0]
    if mutation == "missing_receipt":
        body.pop("lifecycle_value_facts_version")
    if mutation == "macro":
        body["events"][0]["contains_macro"] = True
    if mutation in {"bitfield", "unsigned"}:
        # Explicit negative receipt mutation, separate from actual native positives.
        for event in body["events"]:
            for value in event.get("defs", []) + event.get("uses", []):
                if value.get("value_kind") == "field":
                    value["bit_field" if mutation == "bitfield" else "integer_unsigned"] = True
    assert verify_handle_contract(raw, context) is None


def run_path(project, name):
    from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths

    index, source = project
    return LifecyclePaths(
        index.get_function_program_facts("scenario_" + name, str(source)),
        registered(project),
        index.get_function_program_facts,
    ).run()


@pytest.mark.parametrize(
    "name",
    [
        "zero",
        "retry_preserved",
        "late_error",
        "dup_cleanup",
        "dup_reuse",
        "dup_full",
        "open_full",
        "reopen",
        "wrapped",
        "ops",
        "saturated",
    ],
)
def test_completed_handle_cleanup_has_no_false_observation(handle_project, name):
    result = run_path(handle_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"], result["observations"]
    assert all(r["state"] == "released" for r in result["resources"])
    assert all(
        not o["live_descriptors"] and o["physical_destruction"] == "unproven"
        for o in result["handle_objects"]
    )


@pytest.mark.parametrize(
    "name,expected",
    [
        ("truthiness", {"handle_left_live"}),
        ("failed_close", {"handle_left_live"}),
        ("dup_survives", {"handle_left_live"}),
        ("retry_consumed", {"closed_handle_operation"}),
        ("copy_not_dup", {"closed_handle_operation"}),
        ("closed_dup", {"closed_handle_operation"}),
        ("stale_close", {"stale_handle_generation"}),
        ("stale_dup", {"stale_handle_generation"}),
        ("wrong_table", {"wrong_handle_namespace"}),
    ],
)
def test_handle_observations_keep_exact_identity(handle_project, name, expected):
    result = run_path(handle_project, name)
    assert result["complete"], result["gaps"]
    assert {o["kind"] for o in result["observations"]} == expected


def test_dup_shares_backing_but_not_descriptor_or_close_obligation(handle_project):
    result = run_path(handle_project, "dup_survives")
    first, copy = result["resources"]
    assert first["id"] != copy["id"] and first["handle_value"] == 0 and copy["handle_value"] == 1
    assert first["backing_object_id"] == copy["backing_object_id"]
    assert copy["duplicated_from"] == first["id"]
    assert first["state"] == "released" and copy["state"] == "live"
    assert result["handle_objects"][0]["live_descriptors"] == [copy["id"]]


def test_reopen_same_integer_is_a_new_descriptor_and_new_backing(handle_project):
    result = run_path(handle_project, "stale_close")
    old, fresh = result["resources"]
    assert old["handle_value"] == fresh["handle_value"] == 0
    assert [old["generation"], fresh["generation"]] == [1, 2]
    assert old["id"] != fresh["id"] and old["backing_object_id"] != fresh["backing_object_id"]
    event = result["observations"][0]["event"]
    assert event["saved_resource_id"] == old["id"] and event["actual_resource_id"] == fresh["id"]
    assert fresh["state"] == "released" and event["consumed"]


def test_same_error_status_can_preserve_or_consume_descriptor(handle_project):
    preserved, consumed = (
        run_path(handle_project, name) for name in ("failed_close", "late_error")
    )
    assert preserved["trace"][-1]["return_value"] == consumed["trace"][-1]["return_value"] == -1
    assert preserved["resources"][0]["state"] == "live"
    assert consumed["resources"][0]["state"] == "released"


@pytest.mark.parametrize(
    "name,gap",
    [
        ("unknown_identity", "handle_acquisition_provenance_unknown"),
        ("mutated_live", "handle_table_state_untracked"),
        ("mutated_backing", "handle_backing_identity_untracked"),
        ("sequence_reset", "handle_backing_token_reused"),
        ("unsigned_copy", "handle_conversion_unclosed"),
        ("arithmetic", "integer_type_unclosed"),
    ],
)
def test_unknown_handle_provenance_or_mutation_never_certifies_prefix(handle_project, name, gap):
    result = run_path(handle_project, name)
    assert not result["complete"] and result["gaps"] == [gap]
    assert not result["observations"]


@pytest.mark.parametrize(
    "shape", ["volatile", "atomic", "unsigned", "wide", "bitfield", "union", "attribute", "macro"]
)
def test_real_native_unsupported_storage_and_attributes(tmp_path, shape):
    header = HEADER
    api = "int h_open" + APIS.split("int h_open", 1)[1].split("int h_close", 1)[0]
    if shape in {"volatile", "atomic", "unsigned", "wide"}:
        kind = {
            "volatile": "volatile int",
            "atomic": "_Atomic int",
            "unsigned": "unsigned int",
            "wide": "long long",
        }[shape]
        header = header.replace("int live0", kind + " live0")
    if shape == "bitfield":
        header = "typedef struct Table {int live0:1; int object0,live1,object1,sequence;} Table;\n"
    if shape == "union":
        header = header.replace("struct Table", "union Table")
    if shape == "attribute":
        api = "__attribute__((noinline)) " + api
    if shape == "macro":
        header += "#define FIRST_HANDLE 0\n"
        api = api.replace("return 0;", "return FIRST_HANDLE;")
    source = tmp_path / "negative.c"
    source.write_text(header + api)
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", str(source)],
                }
            ]
        )
    )
    backend, index = native_index(tmp_path, source, database)
    try:
        assert (
            verify_handle_contract(proposal("open"), native_context(index, source, "h_open"))
            is None
        )
    finally:
        backend.close()


def test_unused_call_destination_has_actual_native_integer_type(handle_project):
    index, source = handle_project
    body = index.get_function_program_facts("scenario_dup_survives", str(source))["functions"][0]
    destination = next(
        e["object"]
        for e in body["events"]
        if e.get("event_kind") == "call" and e.get("object", {}).get("name") == "copy"
    )
    assert destination["integer_bits"] == 32 and destination["integer_unsigned"] is False


def test_dup_into_reopened_numeric_slot_keeps_shared_backing(handle_project):
    result = run_path(handle_project, "dup_reuse")
    assert result["complete"] and not result["observations"]
    original, copy, reused = result["resources"]
    assert reused["handle_value"] == original["handle_value"] == 0
    assert reused["generation"] == 2 and original["generation"] == 1
    assert reused["duplicated_from"] == copy["id"]
    assert len({r["backing_object_id"] for r in result["resources"]}) == 1


@pytest.mark.parametrize("name", ["expired_table", "expired_block", "escaped_handle"])
def test_expired_table_cannot_supply_a_live_handle_namespace(handle_project, name):
    result = run_path(handle_project, name)
    assert not result["complete"] and result["gaps"] == ["handle_namespace_lifetime_unclosed"]
    assert not result["observations"]


@pytest.mark.parametrize("numbers", [(0, 3, 7), (0, 3, 7, 11)])
def test_larger_bounded_tables_and_noncontiguous_numbers(tmp_path, numbers):
    from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths

    fields = " ".join(f"int live{i}; int object{i};" for i in range(len(numbers)))
    opening = "int take(Table *t) {if(t->sequence==2147483647) return -1;"
    copying = "int copy(Table *t,int fd) {"
    closing = "int drop(Table *t,int fd,int fail) {if(fail) return -1;"
    for i, n in enumerate(numbers):
        opening += (
            f"if(!t->live{i}) {{t->sequence++;t->object{i}=t->sequence;t->live{i}=1;return {n};}}"
        )
        closing += f"if(fd=={n} && t->live{i}) {{t->live{i}=0;t->object{i}=0;return 0;}}"
        copying += f"if(fd=={n} && t->live{i}) {{"
        for j, m in enumerate(numbers):
            if i != j:
                copying += f"if(!t->live{j}) {{t->object{j}=t->object{i};t->live{j}=1;return {m};}}"
        copying += "return -1;}"
    entry = "void run(void){Table t={0}; int h0=take(&t);"
    entry += "".join(f"int h{i}=copy(&t,h0);" for i in range(1, len(numbers)))
    entry += "".join(f"drop(&t,h{i},0);" for i in range(len(numbers))) + "}"
    source = tmp_path / "bounded.c"
    source.write_text(
        f"typedef struct Table {{{fields} int sequence;}} Table;\n"
        + "\n".join(code + "return -1;}" for code in (opening, copying, closing))
        + "\n"
        + entry
    )
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", str(source)],
                }
            ]
        )
    )
    backend, index = native_index(tmp_path, source, database)
    try:
        registry = ContractRegistry()
        for name, op in [("take", "open"), ("copy", "dup"), ("drop", "close")]:
            raw = proposal(op, "preserves")
            raw["protocol"]["handle_slots"] = [
                {"value": n, "live_path": f"->live{i}", "object_path": f"->object{i}"}
                for i, n in enumerate(numbers)
            ]
            verified = verify_handle_contract(raw, native_context(index, source, name))
            assert verified, name
            registry.add(ApiContract.from_row({"contract": verified}))
        result = LifecyclePaths(
            index.get_function_program_facts("run", str(source)),
            registry,
            index.get_function_program_facts,
        ).run()
        assert result["complete"] and not result["observations"], result["gaps"]
        assert [r["handle_value"] for r in result["resources"]] == list(numbers)
        assert (
            len(result["handle_objects"]) == 1
            and not result["handle_objects"][0]["live_descriptors"]
        )
    finally:
        backend.close()
