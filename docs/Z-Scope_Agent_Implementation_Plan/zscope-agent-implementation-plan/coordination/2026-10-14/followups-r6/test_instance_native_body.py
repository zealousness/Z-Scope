"""Real native conditional definitions may not borrow another variant's body."""
import json
import os

from zscope.config.config import IndexingConfig
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex


def test_conditional_function_body_matches_current_native_instance(tmp_path):
    tool = os.environ["Z_SCOPE_TEST_CLANG_INDEXER"]
    source = tmp_path / "unit.c"
    source.write_text("#ifdef ALT\nvoid f(void) { int ALT_MARKER = 1; }\n#else\nvoid f(void) { int BASE_MARKER = 2; }\n#endif\n", encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([{
        "directory": str(tmp_path), "file": str(source),
        "arguments": ["clang", "-c", str(source), *flags],
    } for flags in ([], ["-DALT=1"])]), encoding="utf-8")
    backend = ClangBackend(frontend="batch", clang_indexer_path=tool, max_threads=2)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        index = CodeIndex(tmp_path, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang"))
        contexts = {row["build_context_id"]: row for row in index.get_build_contexts("unit.c")}
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        assert plan.status == "planned" and len(plan.instances) == 2
        for instance in plan.instances:
            scope = InstanceScope.from_entry_instance(instance)
            view = ScopedCodeIndex(index, scope)
            facts = view.get_function_program_facts("f", "unit.c")
            assert facts["complete"] and facts["function_identity"]["usr"] == scope.usr
            impl = view.get_function_impl("f", file_path="unit.c", include_context=False)
            if impl is None:
                assert view.scope_report()["identity_gaps"] or view.scope_report()["blocked_consumers"]
                continue
            alt = "-DALT=1" in contexts[scope.build_context_id]["command"]["arguments"]
            marker, other = ("ALT_MARKER", "BASE_MARKER") if alt else ("BASE_MARKER", "ALT_MARKER")
            assert marker in impl["code"] and other not in impl["code"], (
                f"body for {scope.build_context_id} borrowed the other variant: {impl['code']}"
            )
    finally:
        backend.close()


def test_same_range_body_cannot_carry_another_variant_callees(tmp_path):
    tool = os.environ["Z_SCOPE_TEST_CLANG_INDEXER"]
    source = tmp_path / "unit.c"
    source.write_text("extern void alt_helper(void);\nextern void base_helper(void);\nvoid f(void) {\n#ifdef ALT\nalt_helper();\n#else\nbase_helper();\n#endif\n}\n", encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([{"directory":str(tmp_path),"file":str(source),
        "arguments":["clang","-c",str(source),*flags]} for flags in ([],["-DALT=1"])]),encoding="utf-8")
    backend=ClangBackend(frontend="batch",clang_indexer_path=tool,max_threads=2)
    try:
        assert backend.initialize(str(tmp_path),compile_commands_path=str(cdb))
        index=CodeIndex(tmp_path,cdb,backend=backend,indexing_config=IndexingConfig(backend="clang"))
        contexts={row["build_context_id"]:row for row in index.get_build_contexts("unit.c")}
        plan=plan_entry_instances(index,[FunctionEntry("f",file_path="unit.c")])
        assert plan.status=="planned" and len(plan.instances)==2
        for instance in plan.instances:
            scope=InstanceScope.from_entry_instance(instance)
            view=ScopedCodeIndex(index,scope)
            assert view.get_function_program_facts("f","unit.c")["complete"]
            impl=view.get_function_impl("f",file_path="unit.c")
            if impl is None:
                assert view.scope_report()["identity_gaps"] or view.scope_report()["blocked_consumers"]
                continue
            alt="-DALT=1" in contexts[scope.build_context_id]["command"]["arguments"]
            expected="alt_helper" if alt else "base_helper"
            assert all(name==expected for name in impl.get("callees",[])), (
                "same source range does not bind the base navigation callee projection: "+str(impl.get("callees"))
            )
    finally:
        backend.close()
