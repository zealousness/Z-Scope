import json

import pytest

from zscope.common.joern_client import JoernClient


@pytest.mark.parametrize(
    "method",
    [
        "get_method",
        "get_method_callers",
        "get_method_callees",
        "get_type_decl",
        "get_type_decls",
        "get_type_members",
        "get_function_type_references",
        "find_methods",
        "find_function_pointers",
    ],
)
def test_model_reachable_names_are_scala_string_literals(method):
    client = object.__new__(JoernClient)
    queries = []
    client.query = lambda query: queries.append(query) or []
    name = 'x"; println("injected")\n\\path\t中文'
    getattr(client, method)(name)
    assert json.dumps(name) in queries[0]
    assert name not in queries[0]


def test_flow_query_preserves_regex_and_escapes_all_three_arguments():
    client = object.__new__(JoernClient)
    queries = []
    client.query = lambda query: queries.append(query) or []
    names = ('root"\n', 'arg\\"\t', r'mem\w+|copy"')
    assert client.get_data_flow_to_sink(*names) == []
    for name in names:
        assert json.dumps(name) in queries[0]
    assert queries[0].count("\n") == 2


@pytest.mark.parametrize("method", ["get_method_callers", "get_function_type_references"])
def test_file_filters_encode_quotes_and_controls(method):
    client = object.__new__(JoernClient)
    queries = []
    client.query = lambda query: queries.append(query) or []
    path = 'src/a"\nfile.c'
    getattr(client, method)(
        "root", **({"callee_file": path} if method == "get_method_callers" else {"file_path": path})
    )
    assert json.dumps(path) in queries[0]
    assert path not in queries[0]
