from zscope.tools.flow_query import FlowQueryService


def test_location_selector_honors_optional_column():
    service = FlowQueryService(None, None)
    graph = {
        "nodes": {
            "first": {"location": {"file": "a.c", "line": 4, "column": 2}},
            "second": {"location": {"file": "a.c", "line": 4, "column": 15}},
        },
        "values": {},
    }
    selector = {"kind": "location", "file_path": "a.c", "line": 4, "column": 15}
    assert service._select_source(graph, selector) == {"second"}
    assert service._select_sink(graph, selector) == {"second"}
    selector.pop("column")
    assert service._select_source(graph, selector) == {"first", "second"}
