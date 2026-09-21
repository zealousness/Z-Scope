from copy import deepcopy

from zscope.core.validation.function_index import function_definitions
from zscope.reporting.shared_objects import ObjectDecoder, ObjectEncoder


def fixture():
    def fn(name):
        return {
            "kind": "FunctionDecl",
            "name": name,
            "inner": [{"kind": "CompoundStmt", "inner": [{"kind": "ReturnStmt"}]}],
        }

    return {
        "ast": {
            "kind": "TranslationUnitDecl",
            "inner": [fn("one"), fn("ambiguous"), fn("ambiguous")],
        }
    }


def test_reused_projection_keeps_all_values_and_modification_isolation(monkeypatch):
    import zscope.core.validation.function_index as module

    plain = fixture()
    expected = function_definitions(plain)
    decoder = ObjectDecoder(ObjectEncoder().envelope(plain))
    first = function_definitions(decoder.decode(decoder.root_node))
    assert first == expected and set(first) == {"one"}
    original = module._collect
    monkeypatch.setattr(
        module, "_collect", lambda ast: (_ for _ in ()).throw(AssertionError("repeated AST walk"))
    )
    second = function_definitions(decoder.decode(decoder.root_node))
    first["one"]["inner"][0]["inner"][0]["kind"] = "Changed"
    assert second == expected
    assert function_definitions(decoder.decode(decoder.root_node)) == expected
    monkeypatch.setattr(module, "_collect", original)
    changed = decoder.decode(decoder.root_node)
    changed["ast"]["inner"][0]["name"] = "renamed"
    assert set(function_definitions(changed)) == {"renamed"}


def test_new_evidence_version_cannot_reuse_previous_function_index():
    old = fixture()
    new = deepcopy(old)
    new["ast"]["inner"][0]["name"] = "replaced"
    a = ObjectDecoder(ObjectEncoder().envelope(old))
    b = ObjectDecoder(ObjectEncoder().envelope(new))
    assert set(function_definitions(a.decode(a.root_node))) == {"one"}
    assert set(function_definitions(b.decode(b.root_node))) == {"replaced"}
