"""Real native callee receipts must not survive a switch to another entry."""
import sys
from pathlib import Path
import os

sys.path.insert(0, str(Path(os.environ["PYTHONPATH"]) / "tests"))
from test_validation_context_workers import native_overloads
from test_contract_usr_scope import _publish
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.core.validation.execution_context import (
    EMPTY_EXECUTION_CONTEXT,
    ExecutionContext,
    rebound_execution_context,
)
from zscope.semantics.call_context import bind_call_context, current_callee_usr
from zscope.semantics.contracts import ContractRegistry
from zscope.semantics.build_scope import current_build_id, current_scope_symbol_usr


def setup_native(index):
    build = index.get_build_contexts("log.cpp")[0]["build_context_id"]
    facts = index.get_function_program_facts("log_event", "log.cpp", build_context_id=build)
    choices = {int(row["line"]): str(row["usr"]) for row in facts["function_choices"]}
    registry = ContractRegistry([])
    _publish(index, registry, func_name="log_event", file_path="log.cpp",
             signature="void log_event(int value)", code="void log_event(int value) {}",
             line=1, usr=choices[1], build=build)
    def context(name, code):
        facts = index.get_function_program_facts(name, "log.cpp", build_context_id=build)
        assert facts["complete"] is True
        return {"func_name": name, "file_path": "log.cpp", "signature": f"void {name}(int mode)",
                "code": code, "program_facts": facts}
    only = context("call_int", "void call_int(int mode) { log_event(mode); }")
    mixed = context("call_mixed", 'void call_mixed(int mode) { if (mode) { log_event(mode); } else { log_event("x"); } }')
    instance = plan_entry_instances(index, [FunctionEntry("call_mixed", file_path="log.cpp")]).instances[0]
    return registry, build, choices[1], only, mixed, instance


def test_switching_entry_does_not_borrow_prior_native_callee_receipt(native_overloads):
    index, _ = native_overloads
    registry, build, int_usr, only, mixed, instance = setup_native(index)
    with bind_call_context(mixed, registry):
        assert registry.match_call("log_event", "io_acquire", ["mode"]) == []
    with bind_call_context(only, registry):
        assert [c.symbol.usr for c in registry.match_call("log_event", "io_acquire", ["mode"])] == [int_usr]
        with rebound_execution_context(ExecutionContext(build, ("call_mixed", instance.usr))):
            assert current_build_id() == build
            assert current_scope_symbol_usr("call_mixed") == instance.usr
            assert registry.match_call("log_event", "io_acquire", ["mode"]) == [], (
                "new entry has mixed overloads; stale call_int receipt cannot grant log_event(int)"
            )
        assert current_callee_usr(registry, "log_event") == int_usr


def test_empty_legacy_rebind_clears_prior_native_callee_identity(native_overloads):
    index, _ = native_overloads
    registry, _, int_usr, only, _, _ = setup_native(index)
    with bind_call_context(only, registry):
        assert current_callee_usr(registry, "log_event") == int_usr
        with rebound_execution_context(EMPTY_EXECUTION_CONTEXT):
            assert current_build_id() == ""
            assert current_callee_usr(registry, "log_event") == "", (
                "legacy empty context must not retain another entry's native callee map"
            )
        assert current_callee_usr(registry, "log_event") == int_usr
