"""Actual native protocol consumer must reject a mismatched publication USR."""
from dataclasses import replace
from pathlib import Path
import sys

import pytest
from zscope.semantics import contracts as contract_module
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths

sys.path.insert(0, str(Path(contract_module.__file__).resolve().parents[2] / "tests"))
from test_refcount_protocols import ref_project, proposals, native_context  # noqa: E402,F401
from test_wrapper_contract_compiler import publish  # noqa: E402


@pytest.mark.parametrize("foreign_usr", ["", "c:@F@foreign_ref_drop"])
def test_actual_protocol_consumer_rejects_unknown_or_foreign_contract_usr(ref_project, tmp_path, foreign_usr):
    index, source = ref_project
    compiled, snapshots = ContractRegistry(), []
    for name, raw in proposals().items():
        context = native_context(index, source, name)
        raw["evidence"][0]["lines"] = str(context["start_line"])
        snapshot = {**context, "interface_contracts": [raw]}
        compile_snapshot(snapshot, context, compiled)
        for row in snapshot["interface_contracts"]:
            compiled.add(ApiContract.from_row({"contract": row}))
        snapshots.append(snapshot)
    _, semantics, _ = publish(tmp_path, snapshots)
    registry = semantics.contracts
    facts = index.get_function_program_facts("ref_drop", str(source))
    interpreter = LifecyclePaths(facts, registry, index.get_function_program_facts)
    body = interpreter._body(facts)
    current = interpreter._contract(body)
    assert current is not None and current.effects_trusted
    assert current.symbol.usr == body["owner"]["usr"] and current.symbol.usr
    foreign = replace(current, symbol=replace(current.symbol, usr=foreign_usr))
    scoped = ContractRegistry()
    scoped.add(foreign)
    rejected = LifecyclePaths(facts, scoped, index.get_function_program_facts)._contract(body)
    assert rejected is None, (body["owner"], rejected.to_dict())
