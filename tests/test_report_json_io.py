import json
from pathlib import Path
import subprocess
import sys

import pytest

from zscope.reporting.json_io import read_json_streaming, write_json_atomic


def test_streaming_reader_preserves_full_payload_and_number_types(tmp_path):
    pytest.importorskip("ijson")
    payload = {
        "issues": [{"description": "资源 🔒", "evidence": [None, False, 1.25, 10**40]}],
        "empty": {},
    }
    path = tmp_path / "report.json"
    write_json_atomic(path, payload)
    actual = read_json_streaming(path)
    assert actual == payload
    assert isinstance(actual["issues"][0]["evidence"][2], float)
    assert isinstance(actual["issues"][0]["evidence"][3], int)


@pytest.mark.parametrize("content", ['{"issues": [', "{} {}", '{"x": true} garbage', ""])
def test_streaming_reader_rejects_incomplete_or_trailing_json(tmp_path, content):
    parser = pytest.importorskip("ijson")
    path = tmp_path / "report.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(parser.JSONError):
        read_json_streaming(path)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux address-space regression")
def test_streaming_reader_does_not_allocate_input_sized_buffer(tmp_path):
    pytest.importorskip("ijson")
    path = tmp_path / "spaced.json"
    with path.open("wb") as stream:
        stream.write(b'{"evidence":')
        for _ in range(100):
            stream.write(b" " * (1024 * 1024))
        stream.write(b"[1,2,3]}")
    code = """
import os, resource, sys
from pathlib import Path
from zscope.reporting.json_io import read_json_streaming, require_streaming_json
require_streaming_json()
current = int(Path('/proc/self/statm').read_text().split()[0]) * os.sysconf('SC_PAGE_SIZE')
limit = current + 48 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
assert read_json_streaming(Path(sys.argv[1])) == {'evidence': [1,2,3]}
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr


def test_report_roundtrip_preserves_unicode_and_never_calls_dumps(tmp_path, monkeypatch):
    expected = {"issues": [{"description": "资源池 Ω 🔒", "lines": [1, 2]}], "partial": True}

    def forbidden(*args, **kwargs):
        raise AssertionError("A complete report-sized string must not be built")

    monkeypatch.setattr(json, "dumps", forbidden)
    path = tmp_path / "nested" / "report.json"
    write_json_atomic(path, expected)
    assert json.loads(path.read_text(encoding="utf-8")) == expected
    assert path.read_bytes().endswith(b"\n")


def test_failed_write_keeps_previous_complete_report(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text('{"previous": true}\n', encoding="utf-8")

    def fail(self, payload, **kwargs):
        yield '{"incomplete":'
        raise MemoryError("simulated serialization failure")

    monkeypatch.setattr(json.JSONEncoder, "iterencode", fail)
    with pytest.raises(MemoryError):
        write_json_atomic(path, {})
    assert json.loads(path.read_text()) == {"previous": True}
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux address-space regression")
def test_large_shared_payload_streams_under_small_extra_memory_limit(tmp_path):
    path = tmp_path / "large.json"
    code = """
import os, resource, sys
from pathlib import Path
from zscope.reporting.json_io import write_json_atomic
payload = {"evidence": ["x" * (512 * 1024) + "🔒"] * 160}
current = int(Path('/proc/self/statm').read_text().split()[0]) * os.sysconf('SC_PAGE_SIZE')
limit = current + 48 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
write_json_atomic(Path(sys.argv[1]), payload)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    assert path.stat().st_size > 80 * 1024 * 1024
