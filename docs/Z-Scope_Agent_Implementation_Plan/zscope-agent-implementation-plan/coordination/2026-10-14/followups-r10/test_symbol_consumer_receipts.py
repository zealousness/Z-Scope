"""Coordinator rejection probes for migrated symbol consumers; native stays real."""
import json
import os
from pathlib import Path
import sys

import zscope

sys.path.insert(0,str(Path(zscope.__file__).resolve().parents[1]/"tests"))
from test_full_symbol_build_scope import _ReceiptIndex, _function_row, _receipt, _scope, _two_contexts
from zscope.retrieval.instance_index import ScopedCodeIndex, InstanceScope
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.config.config import IndexingConfig


def _view(index):
    # Receipt-shape unit probes hold dependency preflight current deliberately.
    # The last probe verifies real native dependencies and cache withdrawal.
    view=ScopedCodeIndex(index,_scope("ctx-alt"))
    view.dependencies_current_status=lambda:"current"
    return view


def test_pinned_call_receipt_positive_is_still_served():
    view=_view(_two_contexts())
    assert [row["name"] for row in view.get_callees("f")]==["alt_helper"]


def test_missing_owner_file_cannot_authorize_callee():
    index=_two_contexts()
    index.rows["ctx-alt"][1]["owner"].pop("file")
    view=_view(index)
    assert view.get_callees("f")==[]


def test_navigation_alias_cannot_bypass_native_owner_line():
    owner={"name":"f","usr":"c:@F@f","file":"unit.c","line":9}
    index=_ReceiptIndex({"ctx-alt":[_function_row("ctx-alt","c:@F@f",2),
        _receipt("call",owner,{"name":"wrong","usr":"c:@F@wrong"},9)]})
    view=_view(index)
    assert view.get_callees("f@unit.c:2-2")==[]


def test_incomplete_native_receipt_cannot_authorize_graph_rows():
    index=_two_contexts()
    index.get_function_program_facts=lambda *a,**kw:{"complete":False,"functions":[],"events":[]}
    view=_view(index)
    assert view.get_callees("f")==[]
    assert view.get_callers("alt_helper")==[]
    assert view.list_functions()==[]


def test_explicit_foreign_callee_file_is_not_ignored():
    view=_view(_two_contexts())
    assert view.get_callers("alt_helper",callee_file="foreign.c")==[]


def test_stale_receipt_cache_is_withdrawn_after_real_header_edit(tmp_path):
    header=tmp_path/"flags.h"
    declaration="typedef struct Flag { int value; } FlagType;\n"
    header.write_text(declaration+"#define FLAG 1\n",encoding="utf-8")
    source=tmp_path/"unit.c"
    source.write_text('#include "flags.h"\nextern void helper(void);\nvoid f(void){ FlagType marker={FLAG}; if(marker.value) helper(); }\n',encoding="utf-8")
    cdb=tmp_path/"compile_commands.json"
    cdb.write_text(json.dumps([{"directory":str(tmp_path),"file":str(source),"arguments":["clang","-c",str(source)]}]),encoding="utf-8")
    backend=ClangBackend(frontend="batch",clang_indexer_path=os.environ["Z_SCOPE_TEST_CLANG_INDEXER"],max_threads=1)
    try:
        assert backend.initialize(str(tmp_path),compile_commands_path=str(cdb))
        index=CodeIndex(tmp_path,cdb,backend=backend,indexing_config=IndexingConfig(backend="clang"))
        ctx=index.get_build_contexts("unit.c")[0]["build_context_id"]
        facts=index.get_function_program_facts("f","unit.c",build_context_id=ctx)
        assert facts["complete"]
        scope=InstanceScope(ctx,facts["function_identity"]["usr"],ctx+":f","unit.c",("f",))
        view=ScopedCodeIndex(index,scope)
        assert [row["name"] for row in view.get_callees("f")]==["helper"]
        assert view.get_function_symbol_context("f")["referenced_macros"]
        assert view.get_function_type_context("f")["referenced_types"]
        header.write_text(declaration+"#define FLAG 0\n",encoding="utf-8")
        assert view.dependencies_current_status()=="stale_build_context"
        assert view.get_callees("f")==[]
        assert view.get_callers("helper")==[]
        assert view.list_functions()==[]
        assert view.get_function_symbol_context("f")["referenced_macros"]==[]
        assert view.get_function_type_context("f")["referenced_types"]==[]
    finally:
        backend.close()


def test_real_native_usr_selects_one_cpp_overload(tmp_path):
    source=tmp_path/"unit.cpp"
    source.write_text("extern void helper_i();\nextern void helper_d();\nvoid f(int){ helper_i(); }\nvoid f(double){ helper_d(); }\n",encoding="utf-8")
    cdb=tmp_path/"compile_commands.json"
    cdb.write_text(json.dumps([{"directory":str(tmp_path),"file":str(source),"arguments":["clang++","-c",str(source)]}]),encoding="utf-8")
    backend=ClangBackend(frontend="batch",clang_indexer_path=os.environ["Z_SCOPE_TEST_CLANG_INDEXER"],max_threads=1)
    try:
        assert backend.initialize(str(tmp_path),compile_commands_path=str(cdb))
        index=CodeIndex(tmp_path,cdb,backend=backend,indexing_config=IndexingConfig(backend="clang"))
        ctx=index.get_build_contexts("unit.cpp")[0]["build_context_id"]
        rows=index.get_compilation_facts(ctx,kinds=("program_function",))
        owner=next(row["owner"] for row in rows if row.get("owner",{}).get("line")==3)
        facts=index.get_function_program_facts(owner["usr"],"unit.cpp",build_context_id=ctx)
        assert facts["complete"]
        scope=InstanceScope(ctx,owner["usr"],ctx+":"+owner["usr"],"unit.cpp",("f",))
        view=ScopedCodeIndex(index,scope)
        assert [row["name"] for row in view.get_callees(scope.usr)]==["helper_i"]
        assert [row["name"] for row in view.get_callees("f")]==["helper_i"]
        aliases=view.get_callees("f@unit.cpp:3-3")
        assert all(row["name"]=="helper_i" for row in aliases)
        if not aliases:
            assert view.scope_report()["scope_gaps"]
    finally:
        backend.close()
