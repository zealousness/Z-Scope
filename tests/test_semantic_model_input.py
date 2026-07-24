import logging

import pytest

from zscope.snapshots.modeling_input import (
    SemanticModelInputError,
    build_semantic_model_input,
    hydrate_project_callee_summaries,
    hydrate_project_callee_summaries_from_map,
)


class FakeCodeIndex:
    def __init__(self, matches, impls=None):
        self.matches = list(matches)
        self.impls = dict(impls or {})
        self.impl_queries = []

    def find_function_infos(self, func_name, file_path=""):
        candidates = [
            item
            for item in self.matches
            if func_name in {
                item.get("function_name"),
                item.get("index_name"),
            }
        ]
        if not file_path:
            return candidates
        return [item for item in candidates if item.get("file_path") == file_path]

    def get_function_impl(self, func_name, **kwargs):
        self.impl_queries.append((func_name, kwargs))
        return self.impls.get(func_name)


def _info(index_name="target@src/target.c:10-20", **overrides):
    payload = {
        "function_name": "target",
        "index_name": index_name,
        "file_path": "src/target.c",
        "start_line": 10,
        "end_line": 20,
        "signature": "int target(void)",
        "is_static": True,
        "is_macro": False,
        "project_callees": [{"callee_index_name": "child", "callsite_lines": [12], "is_static": False}],
        "external_callees": [{"callee_index_name": "printf", "callsite_lines": [13]}],
        "referenced_globals": [{"name": "global_state"}],
        "referenced_macros": [
            {
                "macro_index_name": "LIMIT@include/limits.h:1-1",
                "definition": "1 | #define LIMIT 8\n",
                "is_function_like": False,
                "reference_lines": [10],
            }
        ],
        "referenced_types": [
            {
                "type_index_name": "TargetContext@include/types.h:1-2",
                "kind": "struct",
                "full_definition": "1 | typedef struct { int value; } TargetContext;\n",
                "reference_kinds": ["parameter"],
                "reference_lines": [10],
            }
        ],
    }
    payload.update(overrides)
    return payload


def _impl(index_name="target@src/target.c:10-20"):
    return {
        "func_name": "target",
        "index_name": index_name,
        "file": "src/target.c",
        "start_line": 10,
        "end_line": 20,
        "code": "10 | int target(void) { return 0; }\n",
    }


def test_build_semantic_model_input_uses_unique_function_info_and_indexed_impl():
    info = _info(project_callees_truncation={"returned": 1, "total": 2})
    index = FakeCodeIndex([info], {info["index_name"]: _impl()})

    result = build_semantic_model_input(index, "target", file_path="src/target.c")

    assert result == {
        "func_name": "target",
        "index_name": "target@src/target.c:10-20",
        "file_path": "src/target.c",
        "start_line": 10,
        "end_line": 20,
        "signature": "int target(void)",
        "is_static": True,
        "is_macro": False,
        "code": "10 | int target(void) { return 0; }\n",
        "project_callees": [{"callee_index_name": "child", "callsite_lines": [12], "is_static": False}],
        "external_callees": [{"callee_index_name": "printf", "callsite_lines": [13]}],
        "referenced_globals": [{"name": "global_state"}],
        "referenced_macros": info["referenced_macros"],
        "referenced_types": info["referenced_types"],
        "project_callees_truncation": {"returned": 1, "total": 2},
    }
    assert index.impl_queries[0][0] == info["index_name"]
    assert index.impl_queries[0][1]["max_lines"] is None
    assert "location" not in result


def test_build_semantic_model_input_rejects_missing_or_internal_type_fields() -> None:
    missing = _info()
    missing.pop("referenced_types")
    missing_index = FakeCodeIndex([missing], {missing["index_name"]: _impl()})
    with pytest.raises(SemanticModelInputError) as exc:
        build_semantic_model_input(missing_index, "target")
    assert exc.value.reason == "semantic_model_input_invalid"

    invalid = _info()
    invalid["referenced_types"][0]["definition_hash"] = "must-not-enter-context"
    invalid_index = FakeCodeIndex([invalid], {invalid["index_name"]: _impl()})
    with pytest.raises(SemanticModelInputError) as exc:
        build_semantic_model_input(invalid_index, "target")
    assert exc.value.reason == "semantic_model_input_invalid"

    legacy_location = _info()
    legacy_location["referenced_types"][0]["file_path"] = "include/types.h"
    legacy_location_index = FakeCodeIndex(
        [legacy_location],
        {legacy_location["index_name"]: _impl()},
    )
    with pytest.raises(SemanticModelInputError) as exc:
        build_semantic_model_input(legacy_location_index, "target")
    assert exc.value.reason == "semantic_model_input_invalid"


def test_build_semantic_model_input_copies_optional_type_context() -> None:
    info = _info(
        unresolved_referenced_types=[
            {
                "name": "MissingType",
                "reference_kinds": ["cast"],
                "reference_lines": [15],
                "reason": "type_definition_not_found",
            }
        ],
        referenced_types_truncation={
            "truncated": True,
            "returned": 1,
            "total": 2,
            "definition_bytes_returned": 48,
            "definition_bytes_limit": 32768,
        },
    )
    index = FakeCodeIndex([info], {info["index_name"]: _impl()})

    result = build_semantic_model_input(index, "target")

    assert result["unresolved_referenced_types"] == info[
        "unresolved_referenced_types"
    ]
    assert result["referenced_types_truncation"] == info[
        "referenced_types_truncation"
    ]
    result["referenced_types"][0]["kind"] = "changed"
    assert info["referenced_types"][0]["kind"] == "struct"


def test_build_semantic_model_input_rejects_ambiguous_matches(caplog):
    left = _info("target@src/a.c:10-20", file_path="src/a.c")
    right = _info("target@src/b.c:10-20", file_path="src/b.c")
    index = FakeCodeIndex([left, right])

    with caplog.at_level(logging.WARNING), pytest.raises(SemanticModelInputError) as exc:
        build_semantic_model_input(index, "target")

    assert exc.value.reason == "function_info_ambiguous"
    assert "llm_called=false" in caplog.text
    assert "reason=function_info_ambiguous" in caplog.text


def test_build_semantic_model_input_rejects_missing_match(caplog):
    index = FakeCodeIndex([])

    with caplog.at_level(logging.WARNING), pytest.raises(SemanticModelInputError) as exc:
        build_semantic_model_input(index, "missing")

    assert exc.value.reason == "function_info_not_found"
    assert "reason=function_info_not_found" in caplog.text


def test_build_semantic_model_input_rejects_metadata_impl_mismatch(caplog):
    info = _info()
    impl = _impl()
    impl["file"] = "src/other.c"
    index = FakeCodeIndex([info], {info["index_name"]: impl})

    with caplog.at_level(logging.ERROR), pytest.raises(SemanticModelInputError) as exc:
        build_semantic_model_input(index, "target")

    assert exc.value.reason == "function_info_impl_mismatch"
    assert "reason=function_info_impl_mismatch" in caplog.text


def test_hydrate_project_callee_summaries_reuses_current_snapshot_summary():
    target = _info(
        project_callees=[
            {
                "callee_index_name": "child@src/child.c:1-3",
                "callsite_lines": [12],
                "call_type": ["direct"],
                "is_static": False,
            }
        ],
        external_callees=[],
    )
    child = _info(
        "child@src/child.c:1-3",
        function_name="child",
        file_path="src/child.c",
        start_line=1,
        end_line=3,
        signature="int child(void)",
        project_callees=[],
        external_callees=[],
    )
    index = FakeCodeIndex(
        [target, child],
        {
            target["index_name"]: _impl(),
            child["index_name"]: {
                "func_name": "child",
                "index_name": child["index_name"],
                "file": "src/child.c",
                "start_line": 1,
                "end_line": 3,
                "code": "1 | int child(void) { return 0; }\n",
            },
        },
    )

    class Store:
        def load_snapshot(self, index_name):
            if index_name == child["index_name"]:
                return {"summary": "canonical child summary", "project_callees": []}
            return None

        def needs_refresh(self, index_name, code, context):
            del code, context
            return (False, None) if index_name == child["index_name"] else (True, "no_snapshot")

    context = build_semantic_model_input(index, "target")
    hydrated = hydrate_project_callee_summaries(context, index, Store())

    assert hydrated["project_callees"][0]["callee_summary"] == "canonical child summary"
    assert "callee_summary" not in context["project_callees"][0]


def test_hydrate_self_recursive_callee_reuses_existing_own_summary():
    target = _info(
        project_callees=[
            {
                "callee_index_name": "target@src/target.c:10-20",
                "callsite_lines": [15],
                "call_type": ["direct"],
                "is_static": False,
            }
        ],
        external_callees=[],
    )
    index = FakeCodeIndex([target], {target["index_name"]: _impl()})
    reconciled = []

    class Store:
        def load_snapshot(self, index_name):
            return {
                "index_name": index_name,
                "summary": "existing self summary",
                "project_callees": [],
            }

        def reconcile_project_callee_summaries(self, index_name, context):
            reconciled.append((index_name, context["project_callees"]))
            return "refreshed"

    hydrated = hydrate_project_callee_summaries(
        build_semantic_model_input(index, "target"),
        index,
        Store(),
    )

    assert hydrated["project_callees"][0]["callee_summary"] == "existing self summary"
    assert reconciled[0][1][0]["callee_summary"] == "existing self summary"


def test_summary_map_hydration_ignores_extra_identities_and_preserves_order():
    context = {
        "project_callees": [
            {"callee_index_name": "first", "callsite_lines": [1]},
            {"callee_index_name": "missing", "callsite_lines": [2]},
        ]
    }

    hydrated = hydrate_project_callee_summaries_from_map(
        context,
        {"first": "first summary", "extra": "must be ignored"},
    )

    assert [item["callee_index_name"] for item in hydrated["project_callees"]] == [
        "first",
        "missing",
    ]
    assert [item["callee_summary"] for item in hydrated["project_callees"]] == [
        "first summary",
        "unknown",
    ]
    assert "callee_summary" not in context["project_callees"][0]
