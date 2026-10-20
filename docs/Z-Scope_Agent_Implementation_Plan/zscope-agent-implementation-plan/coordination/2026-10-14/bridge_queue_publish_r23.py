"""Publish complete owner-queue JSON atomically without replacing any request."""
from pathlib import Path
import json
import os
import re
from uuid import uuid4

def publish_complete_bytes(target: Path, data: bytes) -> None:
    temporary = target.with_name("." + target.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Both names are in the same directory/filesystem. link creates the
        # final name atomically and refuses an existing destination. The owner
        # only globs *.request.json, so it never observes the temporary bytes.
        os.link(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)

def publish_request(queue: Path, payload: dict) -> Path:
    identity = payload["id"]
    assert isinstance(identity, str) and re.fullmatch(r"[a-z0-9_-]+", identity)
    assert queue.is_dir()
    target = queue / ("080-" + identity + ".request.json")
    data = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    publish_complete_bytes(target, data)
    return target
