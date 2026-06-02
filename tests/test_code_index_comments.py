from types import SimpleNamespace

from zscope.retrieval.code_index import CodeIndex


def test_function_impl_includes_declaration_and_implementation_comments(tmp_path) -> None:
    include_dir = tmp_path / "include"
    src_dir = tmp_path / "src"
    include_dir.mkdir()
    src_dir.mkdir()

    (include_dir / "demo.h").write_text(
        """#ifndef DEMO_H
#define DEMO_H

/*
 * API contract: value must be non-negative and remains caller-owned.
 */
int documented_api(int value);

#endif
""",
        encoding="utf-8",
    )
    (src_dir / "demo.c").write_text(
        """#include "demo.h"

// Implementation note: preserves zero and rejects negative input.
int documented_api(int value) {
    if (value < 0) {
        return -1;
    }
    return value;
}
""",
        encoding="utf-8",
    )

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    result = index.get_function_impl("documented_api")

    assert result is not None
    assert "API contract: value must be non-negative" in result["code"]
    assert "Implementation note: preserves zero" in result["code"]
    assert [block["kind"] for block in result["comment_blocks"]] == [
        "declaration",
        "implementation",
    ]


def test_regex_index_finds_multiline_header_api_and_implementation(tmp_path) -> None:
    include_dir = tmp_path / "include"
    src_dir = tmp_path / "src"
    include_dir.mkdir()
    src_dir.mkdir()

    (include_dir / "runtime.h").write_text(
        """#ifndef RUNTIME_H
#define RUNTIME_H

int runtime_apply_event(int fd, const char* name,
                        const unsigned char* wire,
                        size_t wire_len,
                        unsigned char* out,
                        size_t out_size);

#endif
""",
        encoding="utf-8",
    )
    (src_dir / "runtime.c").write_text(
        """#include <stddef.h>
#include "runtime.h"

int runtime_apply_event(int fd, const char* name,
                        const unsigned char* wire,
                        size_t wire_len,
                        unsigned char* out,
                        size_t out_size) {
    (void)fd;
    (void)name;
    (void)wire;
    (void)wire_len;
    (void)out;
    return (int)out_size;
}
""",
        encoding="utf-8",
    )

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
        include_paths=[include_dir, src_dir],
    )

    headers = index.get_header_declared_functions(["*.h"])
    assert any(item["name"] == "runtime_apply_event" for item in headers)

    result = index.get_function_impl("runtime_apply_event", include_context=False)
    assert result is not None
    assert result["start_line"] == 4
    assert "runtime_apply_event" in result["code"]


def test_regex_index_supports_cpp_constructors_destructors_and_members(tmp_path) -> None:
    (tmp_path / "widget.cpp").write_text(
        """class Widget {
public:
    Widget();
    ~Widget();
    void inlineMethod() { helper(); }
    void helper() {}
};

// Constructor note: value starts at zero.
Widget::Widget() : value(0) {}

Widget::~Widget() { cleanup(); }

void Widget::bar() { inlineMethod(); }

void cleanup() {}
""",
        encoding="utf-8",
    )

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    functions = set(index.list_functions(limit=50))
    assert {
        "Widget::Widget",
        "Widget::~Widget",
        "Widget::bar",
        "Widget::helper",
        "Widget::inlineMethod",
        "cleanup",
    }.issubset(functions)

    ctor = index.get_function_impl("Widget::Widget")
    assert ctor is not None
    assert "Constructor note: value starts at zero" in ctor["code"]

    dtor = index.get_function_impl("~Widget")
    assert dtor is not None
    assert dtor["func_name"] == "Widget::~Widget"

    member = index.get_function_impl("bar")
    assert member is not None
    assert member["func_name"] == "Widget::bar"


def test_regex_index_keeps_cpp_overloads_addressable_by_signature(tmp_path) -> None:
    (tmp_path / "item.cpp").write_text(
        """struct Item {
    Item() {}
    Item(int value) { (void)value; }
};
""",
        encoding="utf-8",
    )

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    functions = index.list_functions(limit=20)
    assert "Item::Item" in functions
    assert "Item::Item(int value)" in functions
    assert index.get_function_impl("Item::Item") is not None
    assert index.get_function_impl("Item::Item(int value)") is not None


def test_cpp_constructor_impl_includes_header_declaration_comment(tmp_path) -> None:
    include_dir = tmp_path / "include"
    src_dir = tmp_path / "src"
    include_dir.mkdir()
    src_dir.mkdir()

    (include_dir / "gadget.hpp").write_text(
        """class Gadget {
public:
    // Creates a Gadget with caller-owned backing storage.
    Gadget();
};
""",
        encoding="utf-8",
    )
    (src_dir / "gadget.cpp").write_text(
        """#include "gadget.hpp"

Gadget::Gadget() {}
""",
        encoding="utf-8",
    )

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
        include_paths=[include_dir, src_dir],
    )

    result = index.get_function_impl("Gadget::Gadget")

    assert result is not None
    assert "Creates a Gadget with caller-owned backing storage" in result["code"]
    assert result["comment_blocks"][0]["kind"] == "declaration"
