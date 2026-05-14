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
