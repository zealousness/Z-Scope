from pathlib import Path

from zscope.core.candidates.function_facts import (
    function_source_fragment,
    numbered_source_fragment,
)


def test_function_source_fragment_uses_exact_native_cpp_location(tmp_path: Path) -> None:
    source = tmp_path / "unit.cc"
    text = """namespace demo {
class Item {
 public:
  Item(int value);
};

Item::Item(int value) : value_(value) {
  if (value > 0) {
    value_++;
  }
}
}  // namespace demo
"""
    source.write_text(text, encoding="utf-8")
    offset = text.index("Item::Item")
    body = {
        "owner": {"file": str(source), "line": 7, "usr": "c:@N@demo@S@Item@F@Item#I#"},
        "callable": {"location": {"offset": offset}},
    }

    code, start, end = function_source_fragment(body, source_cache={})

    assert start == 7
    assert end == 11
    assert code.startswith("Item::Item(int value)")
    assert "value_++;" in code
    assert code.rstrip().endswith("}")


def test_function_source_fragment_missing_receipt_stays_unavailable() -> None:
    code, start, end = function_source_fragment({"owner": {}}, source_cache={})
    assert (code, start, end) == ("", 0, 0)


def test_numbered_source_fragment_preserves_absolute_native_lines() -> None:
    numbered = numbered_source_fragment("void demo() {\n  sink();\n}", start_line=41)

    assert numbered.splitlines() == [
        "41 | void demo() {",
        "42 |   sink();",
        "43 | }",
    ]
