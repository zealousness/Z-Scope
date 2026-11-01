"""Real linked TUs feed existing object paths and current Validator replay."""

from pathlib import Path

import pytest

from test_link_targets import build_project
from test_single_slot_pool import native_index, native_context, proposal
from test_retention_protocols import proposal as retention_proposal
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.single_slot_pool import verify_single_slot_pool
from zscope.semantics.retention_protocols import verify_retention_contract
from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths


def function(source, name):
    start = source.rindex("static ", 0, source.index(name + "("))
    opened = source.index("{", start)
    depth = 1
    end = opened + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end].removeprefix("static ")


@pytest.fixture
def linked_project(tmp_path):
    original = (Path(__file__).parent / "fixtures/resource_protocols/pool_queue.c").read_text()
    header = original[original.index("typedef") : original.index("static Node")]
    header += "Node *pool_take(Pool *pool);\nvoid pool_give(Pool *pool, Node *node);\n"
    header += "int queue_send(Queue *queue, Node *node, int reject);\nvoid queue_complete(Queue *queue, Pool *pool);\n"
    header += "void cancel_a(Queue *queue, Pool *pool);\n"
    header += "void dispatch(Pool *pool, Node *node, int selection);\nvoid member_dispatch(Pool *pool, Node *node);\n"
    header += (
        "void mutable_dispatch(Pool *pool, Node *node);\nvoid recursive(Pool *pool, Node *node);\n"
    )
    (tmp_path / "api.h").write_text("#include <stddef.h>\n" + header)
    a = '#include "api.h"\n' + "\n".join(
        function(original, n) for n in ("pool_take", "submit_b", "submit_c")
    )
    a += "\nstatic void helper(void) {}\n"
    a += "\nvoid failure_clean(void) { Pool p={0}; Queue q={0}; submit_b(&p,&q,1); queue_complete(&q,&p); }\n"
    a += "\nvoid failure_unreleased(void) { Pool p={0}; Queue q={0}; submit_c(&p,&q,1); queue_complete(&q,&p); }\n"
    a += "\nvoid cancelled_repeat(void) { Pool p={0}; Queue q={0}; submit_b(&p,&q,0); cancel_a(&q,&p); queue_complete(&q,&p); }\n"
    a += "\nint main(void) { return 0; }\n"
    for selection in (0, 1):
        a += f"\nvoid selected_{selection}(void) {{ Pool p={{0}}; Queue q={{0}}; Node *n=pool_take(&p); if (!n) return; queue_send(&q,n,1); dispatch(&p,n,{selection}); }}\n"
    a += "\nvoid member_clean(void) {Pool p={0}; Queue q={0}; Node *n=pool_take(&p); if (!n) return; queue_send(&q,n,1); member_dispatch(&p,n);}\n"
    for entry, target in [
        ("mutable_unknown", "mutable_dispatch"),
        ("recursive_unknown", "recursive"),
    ]:
        a += f"\nvoid {entry}(void) {{Pool p={{0}}; Queue q={{0}}; Node *n=pool_take(&p); if (!n) return; queue_send(&q,n,1); {target}(&p,n);}}\n"
    a += "\nvoid selector_unknown(int choice) {Pool p={0}; Node *n=pool_take(&p); if (!n) return; dispatch(&p,n,choice);}\n"
    b = '#include "api.h"\n' + "\n".join(
        function(original, n) for n in ("pool_give", "queue_send", "queue_complete", "cancel_a")
    )
    b += "\nstatic void helper(void) {}\n"
    b += "\nstatic void keep(Pool *pool, Node *node) {}\nstatic void (*const actions[])(Pool *,Node *)={pool_give,keep};\n"
    b += "void dispatch(Pool *pool, Node *node, int selection) {actions[selection](pool,node);}\n"
    b += "static const struct Ops {void (*drop)(Pool *,Node *);} ops={pool_give};\n"
    b += "void member_dispatch(Pool *pool, Node *node) {ops.drop(pool,node);}\n"
    b += "static void (*mutable_actions[])(Pool *,Node *)={pool_give};\nvoid mutable_dispatch(Pool *pool, Node *node) {mutable_actions[0](pool,node);}\n"
    b += "void recursive(Pool *pool, Node *node) {recursive(pool,node);}\n"
    database, command, receipt = build_project(tmp_path, {"a.c": a, "b.c": b})
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    registry = ContractRegistry()
    for file, name, raw, verify in [
        ("a.c", "pool_take", proposal("allocator"), verify_single_slot_pool),
        ("b.c", "pool_give", proposal("deallocator"), verify_single_slot_pool),
        ("b.c", "queue_send", retention_proposal(), verify_retention_contract),
    ]:
        ctx = native_context(index, tmp_path / file, name)
        row = verify(raw, ctx)
        assert row, ctx
        registry.add(ApiContract.from_row({"contract": row}))
    try:
        yield index, tmp_path, registry, receipt, command
    finally:
        backend.close()


def analyze(project, name):
    index, root, registry, _, _ = project
    facts = index.get_function_program_facts(name, str(root / "a.c"))
    return LifecyclePaths(facts, registry, index.get_function_program_facts).run()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("failure_clean", []),
        ("failure_unreleased", ["failed_retention_unreleased"]),
        ("cancelled_repeat", ["repeat_return"]),
        ("selected_0", []),
        ("selected_1", ["failed_retention_unreleased"]),
        ("member_clean", []),
    ],
)
def test_actual_cross_tu_object_and_cleanup(linked_project, name, expected):
    result = analyze(linked_project, name)
    assert result["complete"], result["gaps"]
    assert result["scope"] == "concrete_linked_c_entry_path"
    assert result["link_target"]["target_id"] == linked_project[3]["target_id"]
    assert len({v["build_context_id"] for v in result["function_bindings"].values()}) == 2
    assert [o["kind"] for o in result["observations"]] == expected
    assert not result["proof_authority"]
    if name == "failure_clean":
        assert result["resources"] and all(r["state"] == "released" for r in result["resources"])


@pytest.mark.parametrize("change", ["receipt", "binary", "callee", "object"])
def test_stale_or_absent_link_cannot_certify_path(linked_project, change):
    _, root, _, _, _ = linked_project
    if change == "receipt":
        for path in (root / ".zscope-link-targets").glob("*.json"):
            path.unlink()
    else:
        path = root / {"binary": "app", "callee": "b.c", "object": "b.o"}[change]
        path.write_bytes(path.read_bytes() + b"\n")
    result = analyze(linked_project, "failure_unreleased")
    assert not result["complete"] and result["gaps"]
    assert result["observations"] == []


@pytest.mark.parametrize("name", ["mutable_unknown", "recursive_unknown", "selector_unknown"])
def test_unclosed_dispatch_cannot_mean_all_targets_release(linked_project, name):
    result = analyze(linked_project, name)
    assert not result["complete"] and result["gaps"] and not result["observations"]


def test_linked_candidate_replay_is_current_and_reopens_after_artifact_change(linked_project):
    from test_lifecycle_paths import candidates
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.protocol_assessment import assess_protocol_candidate

    index, root, registry, receipt, _ = linked_project
    (issue,) = candidates((index, root / "a.c", registry), "failure_unreleased")
    attach_decision_facts(issue)
    assessment = assess_protocol_candidate(issue, index, registry)
    # The dedicated obligation consumes the current linked path while keeping
    # business responsibility unconfirmed; replay alone never confirms a defect.
    assert assessment["state"] == "conditional", assessment
    assert assessment["technical_gaps"] == []
    assert {a["fact_kind"] for a in assessment["assumptions"]} == {
        "event:business_release_requirement",
        "event:responsibility_endpoint",
    }
    assert all(a["status"] == "unconfirmed" for a in assessment["assumptions"])
    assert assessment["technical_witness_current"]
    assert assessment["link_target"]["target_id"] == receipt["target_id"]
    assert {r["symbol"]["build_context_id"] for r in assessment["source_refs"]} == set(
        receipt_builds := issue["evidence_pack"]["object_protocol_path"]["link_target"]["members"]
    )
    assert len(receipt_builds) == 2 and not assessment["proof_authority"]
    output = root / "app"
    output.write_bytes(output.read_bytes() + b"\n")
    replay = assess_protocol_candidate(issue, index, registry)
    assert replay["state"] == "pending" and not replay["technical_witness_current"]


def test_target_table_rewrite_invalidates_receipt_and_old_path(linked_project):
    from zscope.retrieval.link_targets import record_link, receipt_status

    index, root, registry, before, command = linked_project
    original = analyze(linked_project, "selected_0")
    assert original["complete"] and not original["observations"]
    source = root / "b.c"
    source.write_text(source.read_text().replace("={pool_give,keep}", "={keep,pool_give}"))
    assert receipt_status(before) == "stale_link_inputs"
    after = record_link(root, root / "compile_commands.json", command, directory=root)
    assert after["target_id"] != before["target_id"]
    result = analyze(linked_project, "selected_0")
    assert not result["complete"] and not result["observations"]  # Old native/contract snapshot.


def test_current_linked_path_obeys_default_disabled_rule(linked_project):
    from test_lifecycle_paths import candidates, RULE
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    index, root, registry, _, _ = linked_project
    for enabled, disabled, present in [
        ([], [], False),
        ([RULE], [], True),
        ([RULE], [RULE], False),
    ]:
        policy = EffectiveRuleSet.build(
            RuleCatalog.builtin(),
            language="c_cpp",
            backend="clang",
            enabled_ids=enabled,
            disabled_ids=disabled,
        ).policy
        assert (
            bool(candidates((index, root / "a.c", registry), "failure_unreleased", policy))
            == present
        )
