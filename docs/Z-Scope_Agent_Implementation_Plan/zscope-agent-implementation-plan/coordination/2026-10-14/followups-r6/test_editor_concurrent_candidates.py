"""Coordinator probe: concurrent valid writes must own distinct candidate files."""

from concurrent.futures import ThreadPoolExecutor
import threading

import yaml

from zscope.config import editor


def test_two_concurrent_valid_documents_keep_their_own_contents(tmp_path, monkeypatch):
    # The writes share one service process and directory, as real threaded HTTP does.
    documents = [
        {"config_version": 3,
         "llms": {"default": {"base_urls": ["http://dummy.invalid/v1"],
                                "models": ["dummy"], "api_key": "dummy"}},
         "project": {"root": ".", "language": "java", "targets": [{"id": name}]},
         "scan": {"preset": "quick"}}
        for name in ("alpha", "beta")
    ]
    texts = [yaml.safe_dump(document) for document in documents]
    targets = [tmp_path / "alpha.yaml", tmp_path / "beta.yaml"]
    barrier = threading.Barrier(2)
    write = editor._write_text

    def synchronized_write(path, text):
        write(path, text)
        barrier.wait(timeout=10)

    monkeypatch.setattr(editor, "_write_text", synchronized_write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(editor.save_document_text, target, text)
                   for target, text in zip(targets, texts)]
        for future in futures:
            assert future.result(timeout=20)["success"] is True
    for target, text in zip(targets, texts):
        assert target.read_text(encoding="utf-8") == text
    assert not list(tmp_path.glob(".zscope-config-editor*"))
