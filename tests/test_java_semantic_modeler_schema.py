from zscope.agents.semantic_modeler.agent import _schema_json
from zscope.agents.semantic_modeler.schema import snapshot_schema_for_language


def test_java_snapshot_schema_is_selected_by_language() -> None:
    schema = snapshot_schema_for_language("java")

    assert schema["properties"]["language"]["const"] == "java"
    assert "framework_entry" in schema["required"]
    assert "security_checks" in schema["required"]
    assert "sinks" in schema["required"]


def test_schema_json_uses_java_schema_when_no_explicit_schema() -> None:
    text = _schema_json(None, "java")

    assert '"language": {' in text
    assert '"java"' in text
    assert "framework_entry" in text
