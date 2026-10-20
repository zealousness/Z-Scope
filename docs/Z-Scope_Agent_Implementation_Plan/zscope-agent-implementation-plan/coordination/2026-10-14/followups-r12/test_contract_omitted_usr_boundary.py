"""Omission is unknown identity, including actual native mixed overload calls.

The first two cases are synthetic selection isolation, not native extraction.
The third uses the actual clang-indexer and compiler publication; it checks
symbol selection without claiming the fixture's io_acquire role is proved.
"""
from test_contract_usr_boundary import compiled
from test_contract_usr_scope import native_index, _build_for, _publish
from zscope.semantics.build_scope import bind_build_scope
from zscope.semantics.call_context import bind_call_context, callee_usr_map
from zscope.semantics.contracts import ContractRegistry


def test_omitted_unknown_identity_cannot_grant_a_precise_published_effect():
    context, registry, contract = compiled()
    with bind_build_scope({"build_context_id":"build-a"}):
        assert registry.match_call("dispose","deallocator",["p"],usr=contract.symbol.usr,facts={"p":{"non_null_identity":"p"}})
        assert not registry.match_call("dispose","deallocator",["p"],usr="",facts={"p":{"non_null_identity":"p"}})
        assert not registry.match_call("dispose","deallocator",["p"],facts={"p":{"non_null_identity":"p"}})


def test_effect_lookup_omission_cannot_select_a_pinned_contract_without_identity():
    context, registry, contract = compiled()
    with bind_build_scope({"build_context_id":"build-a"}):
        assert registry.find_for_call("dispose","deallocator",usr=contract.symbol.usr)==[contract]
        assert registry.find_for_call("dispose","deallocator")==[]


def test_real_mixed_callees_cannot_borrow_the_only_published_overload(native_index):
    index, root = native_index
    build = _build_for(index,"log.cpp")
    choices = index.get_function_program_facts("log_msg","log.cpp",build_context_id=build)
    owners={int(row["line"]):str(row["usr"]) for row in choices["function_choices"]}
    registry=ContractRegistry([])
    _publish(index,registry,func_name="log_msg",file_path="log.cpp",signature="void log_msg(int value)",code="void log_msg(int value) {}",line=1,usr=owners[1],build=build)
    exact=index.get_function_program_facts("only_int","log.cpp",build_context_id=build)
    with bind_call_context({"func_name":"only_int","file_path":"log.cpp","signature":"void only_int(int mode)","code":"void only_int(int mode) { log_msg(mode); }","program_facts":exact},registry):
        assert [row.symbol.usr for row in registry.match_call("log_msg","io_acquire",["mode"])]==[owners[1]]
    facts=index.get_function_program_facts("mixed","log.cpp",build_context_id=build)
    assert facts["complete"] and callee_usr_map({"program_facts":facts})=={}
    context={"func_name":"mixed","file_path":"log.cpp","signature":"void mixed(int mode)","code":'void mixed(int mode) { if (mode) { log_msg(mode); } else { log_msg("x"); } }',"program_facts":facts}
    with bind_call_context(context,registry):
        assert registry.match_call("log_msg","io_acquire",["mode"])==[]
