import logging

import pytest

from zscope.snapshots.modeling_input import (
    SemanticModelInputError,
    build_semantic_model_input,
)


class FakeCodeIndex:
    def __init__(self, matches, impls=None):
        self.matches = list(matches)
        self.impls = dict(impls or {})
        self.impl_queries = []

    def find_function_infos(self, func_name, file_path=""):
        del func_name
        if not file_path:
            return list(self.matches)
        return [item for item in self.matches if item.get("file_path") == file_path]

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
        "callees": [{"callee_index_name": "child", "callsite_lines": [12]}],
        "referenced_globals": [{"name": "global_state"}],
        "referenced_macros": [{"name": "LIMIT"}],
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
    info = _info(callees_truncation={"returned": 1, "total": 2})
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
        "callees": [{"callee_index_name": "child", "callsite_lines": [12]}],
        "referenced_globals": [{"name": "global_state"}],
        "referenced_macros": [{"name": "LIMIT"}],
        "callees_truncation": {"returned": 1, "total": 2},
    }
    assert index.impl_queries[0][0] == info["index_name"]
    assert index.impl_queries[0][1]["max_lines"] is None
    assert "location" not in result


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
