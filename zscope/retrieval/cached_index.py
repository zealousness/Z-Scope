"""An existing-state source facade for read-only MCP, without backend startup.

Cached symbols are navigation hints. Legacy KnowledgeDB does not expose a
standalone complete freshness receipt; graph/flow requests remain unavailable
until that identity can be established, instead of silently rebuilding facts.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..common.readonly import ReadonlyStateError, readonly_database


class CachedCodeIndex:
    cache_only = True
    _backend = None
    _index_epoch = 0

    def __init__(self, config: Any):
        self.project_root = Path(config.project.project_root).resolve()
        self.source_root = Path(config.project.source_root).resolve()
        self.exclude_paths = config.project.exclude_paths
        self.backend_name = config.indexing.backend
        self.language = config.project.language
        self._function_index: dict[str, dict[str, Any]] = {}
        self.cache_status = "unavailable"
        db_path = Path(config.indexing.knowledge_db_path)
        try:
            relative = db_path.absolute().relative_to(self.project_root).as_posix()
            with readonly_database(self.project_root, relative) as conn:
                rows = []
                payload_bytes = 0
                for row in conn.execute(
                    "SELECT name, file_path, start_line, end_line, signature FROM functions WHERE is_declaration=0 ORDER BY name, file_path, start_line LIMIT 100001"
                ):
                    payload_bytes += sum(len(str(value).encode("utf-8")) for value in row)
                    if payload_bytes > 16 * 1024 * 1024:
                        return
                    rows.append(row)
            if len(rows) > 100000:
                return
            for row in rows:
                raw = str(row["file_path"])
                path = Path(raw)
                if path.is_absolute():
                    try:
                        raw = path.relative_to(self.project_root).as_posix()
                    except ValueError:
                        continue
                # Avoid importing tools in the retrieval layer. The source
                # boundary and corpus checks are applied by the catalog/tools.
                name = str(row["name"])
                key = (
                    name
                    if name not in self._function_index
                    else f"{name}@{raw}:{row['start_line']}"
                )
                self._function_index[key] = {
                    "name": name,
                    "file": raw,
                    "start_line": row["start_line"],
                    "end_line": row["end_line"],
                    "signature": row["signature"],
                }
            self.cache_status = "unverifiable"
        except (OSError, sqlite3.Error, ReadonlyStateError, ValueError):
            pass

    def close(self) -> None:
        pass  # Every read transaction closes its owned connection immediately.
