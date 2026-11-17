"""Shared configuration editor backend for Web/MCP structured editing.

This module is the small coordination service behind the structured config
editor: a read projection that keeps the original document verbatim and a
save path that validates the candidate in the configuration's own directory
before an atomic replace.  It is wired into ``ConfigService`` by the
coordinator; no route or service is modified here.

The read projection returns the raw document (every llms profile, relative
path, and ``${VAR}`` environment reference) together with the actual
``config_version`` — the same ``config`` / ``config_version`` / ``language``
keys the existing ``GET /api/config/structured`` contract serves.

Saving never builds a second parser or a weakened schema.  A v3 candidate is
validated with ``v3.parse_user_config_v3`` — the formal model without
composing execution — so a multi-target document can be legally edited and
saved while the single-target execution chain still refuses to run it.
The candidate is always materialized as a temporary file in the same
directory first, because configurations use the
configuration file directory as their only project root; validation failure raises before any replace,
so the saved file is never overwritten with an invalid document.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping

import yaml

from .support import ENV_PATTERN, load_yaml_unique
from .v3 import parse_user_config_v3, parse_user_config_v3_document

STRUCTURED_DOCUMENT_HEADER = (
    "# Z-SCOPE 配置文件\n"
    "# 本文件由结构化配置编辑器生成。\n"
    "# 字段说明请参考仓库根目录 zscope.c_cpp.yaml 或 zscope.java.yaml 中的注释。\n\n"
)


def read_structured_document(config_path: Path | str) -> Dict[str, Any]:
    """Return the original document plus its actual version for the editor.

    The document is read without environment expansion, so profile tables,
    relative paths, and ``${VAR}`` references survive exactly as saved.  A
    missing or empty file projects as an empty document with a null version,
    matching the existing editor behavior for not-yet-configured projects.
    """

    path = Path(config_path)
    if not path.exists():
        return {"config": {}, "config_version": None, "language": None}
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return {"config": {}, "config_version": None, "language": None}
    # The unique-key loader refuses duplicate mapping keys on read: silently
    # accepting them here would let a later save drop one of the duplicates.
    document = load_yaml_unique(path)
    return {
        "config": document,
        "config_version": document.get("config_version"),
        "language": (document.get("project") or {}).get("language"),
    }


def _available_environment(document: Any) -> tuple[Any, Dict[str, list[str]]]:
    """Resolve available variables for validation, retaining missing references."""
    unresolved: Dict[str, list[str]] = {}

    def expand(value: Any, path: str) -> Any:
        if isinstance(value, dict):
            return {
                key: expand(item, f"{path}.{key}" if path else key) for key, item in value.items()
            }
        if isinstance(value, list):
            return [expand(item, f"{path}[{index}]") for index, item in enumerate(value)]
        if not isinstance(value, str):
            return value

        def replace(match: Any) -> str:
            name = match.group(1) or match.group(2)
            if name in os.environ:
                return os.environ[name]
            unresolved.setdefault(path, []).append(name)
            return str(match.group(0))

        return ENV_PATTERN.sub(replace, value)

    return expand(document, ""), unresolved


def validate_document_file(path: Path, *, expand_environment: bool = True) -> None:
    """Validate the only public schema, including every declared target."""
    if expand_environment:
        parse_user_config_v3(str(path))
        return
    available, unresolved = _available_environment(load_yaml_unique(path))
    try:
        parse_user_config_v3_document(Path(path), available)
    except ValueError as error:
        for field, names in unresolved.items():
            if field in str(error) and "removed:" not in str(error):
                raise ValueError(
                    f"{error}; cannot structurally validate {field} while "
                    f"environment variable(s) are unset: {', '.join(sorted(set(names)))}"
                ) from error
        raise


def validate_document_text(
    text: str, *, config_dir: Path | str, expand_environment: bool = True
) -> None:
    """Validate candidate text as if it were saved in ``config_dir``.

    The candidate is materialized in ``config_dir`` itself because v3
    uses the configuration file directory as its only project root; nothing is
    written to the real configuration file.
    """

    with _candidate_file(config_dir) as temporary:
        _write_text(temporary, text)
        validate_document_file(temporary, expand_environment=expand_environment)


def save_document_text(
    config_path: Path | str, text: str, *, expand_environment: bool = True
) -> Dict[str, Any]:
    """Atomically replace the saved configuration with validated text.

    Validation failure raises before the replace, leaving the saved file and
    its bytes untouched; the temporary candidate is always removed.
    """

    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    from .semantics_workflow import project_activity

    with project_activity(path.parent, wait_seconds=0.5), _candidate_file(path.parent, name=path.name) as temporary:
        _write_text(temporary, text)
        validate_document_file(temporary, expand_environment=expand_environment)
        os.replace(temporary, path)
    return {"success": True, "path": str(path)}


def save_document_data(
    config_path: Path | str, document: Mapping[str, Any], *, expand_environment: bool = True
) -> None:
    """Serialize and save a structured document, preserving its raw values.

    The document is dumped verbatim (no normalization, no environment
    expansion), so profiles, relative paths, and ``${VAR}`` references are
    retained; validity is enforced by :func:`save_document_text`.
    """

    text = yaml.safe_dump(dict(document), allow_unicode=True, sort_keys=False)
    save_document_text(
        config_path, STRUCTURED_DOCUMENT_HEADER + text, expand_environment=expand_environment
    )


def _write_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


@contextmanager
def _candidate_file(
    config_dir: Path | str, *, name: str = "zscope-config-editor"
) -> Iterator[Path]:
    """One temporary candidate file inside the configuration's directory.

    The name carries the process and thread identity so a threaded Web
    server saving different (or the same) configuration concurrently never
    shares one candidate file.
    """

    directory = Path(config_dir)
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f".{name}.tmp-{os.getpid()}-{threading.get_ident()}"
    try:
        yield temporary
    finally:
        if temporary.exists():
            temporary.unlink()
