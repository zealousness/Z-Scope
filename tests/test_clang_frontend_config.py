from types import SimpleNamespace

import pytest

from zscope.config.config import IndexingConfig
from zscope.config.v2 import _parse_indexing


@pytest.mark.parametrize("frontend", ["auto", "batch", "lsp"])
def test_optional_clang_frontend_configuration(frontend):
    config = _parse_indexing(
        {
            "backend": "clang",
            "clang": {"frontend": frontend},
            "tools": {"clang_indexer": "/opt/indexer"},
        },
        language="c_cpp",
        runtime=SimpleNamespace(knowledge_db_path="code.db"),
    )
    assert config.clang_frontend == frontend
    assert config.clang_indexer_path == "/opt/indexer"


def test_default_auto_and_invalid_frontend():
    assert IndexingConfig().clang_frontend == "auto"
    with pytest.raises(ValueError, match="indexing.clang.frontend"):
        IndexingConfig(clang_frontend="typo")


def test_java_rejects_clang_frontend():
    with pytest.raises(ValueError, match="not valid for Java"):
        _parse_indexing(
            {"backend": "java_source", "clang": {"frontend": "batch"}},
            language="java",
            runtime=SimpleNamespace(knowledge_db_path="code.db"),
        )


def test_explicit_missing_indexer_does_not_silently_start_lsp(tmp_path, monkeypatch):
    from zscope.retrieval.clang_backend import ClangBackend

    backend = ClangBackend(frontend="auto", clang_indexer_path=str(tmp_path / "missing"))
    monkeypatch.setattr(backend, "_ensure_extractor", lambda: pytest.fail("unexpected LSP"))
    (tmp_path / "sample.c").write_text("int sample(void) { return 1; }\n")
    try:
        assert backend.initialize(str(tmp_path)) is False
    finally:
        if backend.db:
            backend.db.close()
