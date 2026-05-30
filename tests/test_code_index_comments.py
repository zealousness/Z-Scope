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
