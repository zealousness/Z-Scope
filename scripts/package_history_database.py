#!/usr/bin/env python3
"""Package Z-SCOPE history databases for frontend download."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sqlite3
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover - runtime guard
    yaml = None


DEFAULT_HISTORY_PATTERNS = (
    ".zscope_snapshots/snapshots.db",
    ".zscope_snapshots/*.json",
    ".zscope_snapshots/*.xlsx",
    ".zscope_knowledge/*.db",
    ".zscope_knowledge/*.sqlite",
    ".zscope_knowledge/*.sqlite3",
)
SNAPSHOT_DIR_PATTERNS = ("snapshots.db", "*.json", "*.xlsx", "*.db", "*.sqlite", "*.sqlite3")
ALLOWED_PATTERN_ROOTS = (".zscope_snapshots", ".zscope_knowledge")
DEFAULT_MAX_FILES = 10000
DEFAULT_MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024
DEFAULT_MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024 * 1024
SQLITE_HEADER = b"SQLite format 3\x00"


@dataclass(frozen=True)
class HistorySource:
    source_path: Path
    archive_path: str
    source_kind: str
    is_sqlite: bool
    size_bytes: int
    logical_source: str


@dataclass(frozen=True)
class PackagedFile:
    archive_path: str
    source_kind: str
    packaging_method: str
    size_bytes: int
    sha256: str


class HistoryPackageError(RuntimeError):
    def __init__(self, message: str, *, code: str, stage: str):
        super().__init__(message)
        self.code = code
        self.stage = stage


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package Z-SCOPE history database artifacts into a tar.gz archive."
    )
    parser.add_argument("--project-root", required=True, help="Target project root on the scan environment.")
    parser.add_argument("--output", default="", help="Output .tar.gz path. Defaults under project root.")
    parser.add_argument(
        "--config",
        default="",
        help="Optional zscope.yaml path. Defaults to <project-root>/zscope.yaml when that file exists.",
    )
    parser.add_argument("--snapshot-dir", default="", help="Explicit snapshot directory. Overrides zscope.yaml.")
    parser.add_argument("--knowledge-db-path", default="", help="Explicit code knowledge database path. Overrides zscope.yaml.")
    parser.add_argument(
        "--user-config-db",
        default="",
        help="Explicit user configuration database/workbook path. Overrides zscope.yaml.",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Additional safe project-root-relative glob under .zscope_snapshots/ or .zscope_knowledge/. Repeat for multiple patterns.",
    )
    parser.add_argument("--overwrite", action="store_true", help="Atomically replace an existing output archive.")
    parser.add_argument("--dry-run", action="store_true", help="Discover and validate sources without creating an archive.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help=f"Maximum source files. Default: {DEFAULT_MAX_FILES}.")
    parser.add_argument(
        "--max-total-bytes",
        type=int,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help=f"Maximum total source bytes. Default: {DEFAULT_MAX_TOTAL_BYTES}.",
    )
    parser.add_argument(
        "--max-single-file-bytes",
        type=int,
        default=DEFAULT_MAX_SINGLE_FILE_BYTES,
        help=f"Maximum single source file bytes. Default: {DEFAULT_MAX_SINGLE_FILE_BYTES}.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args(argv)


def package_history_database(args: argparse.Namespace) -> dict[str, Any]:
    archive_path = ""
    try:
        return _package_history_database(args)
    except HistoryPackageError as exc:
        archive_path = output_path_from_args(args, Path(getattr(args, "project_root", "."))).as_posix()
        return error_payload(exc, archive_path=archive_path)
    except OSError as exc:
        archive_path = output_path_from_args(args, Path(getattr(args, "project_root", "."))).as_posix()
        return error_payload(
            HistoryPackageError(str(exc), code="ARCHIVE_WRITE_FAILED", stage="write_archive"),
            archive_path=archive_path,
        )


def _package_history_database(args: argparse.Namespace) -> dict[str, Any]:
    project_root = Path(args.project_root).expanduser().resolve()
    if not project_root.exists() or not project_root.is_dir():
        raise HistoryPackageError(
            f"project_root does not exist or is not a directory: {project_root}",
            code="INVALID_PROJECT_ROOT",
            stage="validate_project_root",
        )

    limits = {
        "max_files": int(args.max_files),
        "max_total_bytes": int(args.max_total_bytes),
        "max_single_file_bytes": int(args.max_single_file_bytes),
    }
    output = output_path_from_args(args, project_root)
    config_path, config_data = load_history_config(project_root, args.config)
    resolved_sources = resolve_history_locations(project_root, config_data, args)
    sources, warnings = collect_history_sources(project_root, resolved_sources, tuple(args.pattern or ()), output)
    enforce_limits(sources, limits)

    base_payload = {
        "project_root": str(project_root),
        "config_path": str(config_path) if config_path else "",
        "resolved_sources": {key: str(value) if value else "" for key, value in resolved_sources.items()},
        "archive_path": str(output),
        "archive_format": "tar.gz",
        "dry_run": bool(args.dry_run),
        "source_file_count": len(sources),
        "source_total_bytes": sum(source.size_bytes for source in sources),
        "limits": limits,
        "warnings": warnings,
    }

    if not sources:
        raise HistoryPackageError("no history database files found", code="NO_HISTORY_FILES", stage="collect_sources")
    if output.exists() and not args.overwrite and not args.dry_run:
        raise HistoryPackageError(f"output archive already exists: {output}", code="OUTPUT_EXISTS", stage="validate_output")

    if args.dry_run:
        return {
            "success": True,
            **base_payload,
            "files": [source_to_payload(source) for source in sources],
        }

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        packaged_files, temp_archive = write_archive(project_root, sources, output, warnings)
        verified = verify_archive(temp_archive, [item.archive_path for item in packaged_files])
        digest = calculate_sha256(temp_archive)
        os.replace(temp_archive, output)
    except HistoryPackageError:
        raise
    except OSError as exc:
        raise HistoryPackageError(str(exc), code="ARCHIVE_WRITE_FAILED", stage="write_archive") from exc
    finally:
        if "temp_archive" in locals() and Path(temp_archive).exists():
            Path(temp_archive).unlink(missing_ok=True)

    archive_size = output.stat().st_size
    return {
        "success": True,
        **base_payload,
        "dry_run": False,
        "archive_size_bytes": archive_size,
        "sha256": digest,
        "verified": verified,
        "manifest_member": "MANIFEST.json",
        "file_count": len(packaged_files),
        "files": [item.__dict__ for item in packaged_files],
    }


def output_path_from_args(args: argparse.Namespace, project_root: Path) -> Path:
    output = Path(getattr(args, "output", "")).expanduser() if getattr(args, "output", "") else _default_output_path(project_root)
    return output if output.is_absolute() else project_root / output


def _default_output_path(project_root: Path) -> Path:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return project_root / f"zscope_history_database_{run_id}.tar.gz"


def load_history_config(project_root: Path, config_arg: str) -> tuple[Path | None, dict[str, Any]]:
    explicit = bool(config_arg)
    config_path = Path(config_arg).expanduser() if config_arg else project_root / "zscope.yaml"
    if not config_path.is_absolute():
        config_path = project_root / config_path
    if not config_path.exists():
        if explicit:
            raise HistoryPackageError(f"config file not found: {config_path}", code="CONFIG_NOT_FOUND", stage="load_config")
        return None, {}
    if yaml is None:
        raise HistoryPackageError("PyYAML is required to read zscope.yaml", code="CONFIG_INVALID", stage="load_config")
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise HistoryPackageError(str(exc), code="CONFIG_INVALID", stage="load_config") from exc
    if not isinstance(data, dict):
        raise HistoryPackageError("zscope.yaml root must be an object", code="CONFIG_INVALID", stage="load_config")
    return config_path, data


def resolve_history_locations(project_root: Path, config: dict[str, Any], args: argparse.Namespace) -> dict[str, Path | None]:
    analysis = config.get("analysis") if isinstance(config.get("analysis"), dict) else {}
    indexing = config.get("indexing") if isinstance(config.get("indexing"), dict) else {}
    snapshot_dir = args.snapshot_dir or analysis.get("snapshot_dir") or ".zscope_snapshots"
    knowledge_db_path = args.knowledge_db_path or indexing.get("knowledge_db_path") or ".zscope_knowledge/code_knowledge.db"
    user_config_db = args.user_config_db or analysis.get("user_config_db") or ""
    resolved_snapshot = resolve_config_path(project_root, str(snapshot_dir))
    resolved_knowledge = resolve_config_path(project_root, str(knowledge_db_path))
    resolved_user = resolve_user_config_path(project_root, resolved_snapshot, str(user_config_db)) if user_config_db else None
    return {
        "snapshot_dir": resolved_snapshot,
        "knowledge_db_path": resolved_knowledge,
        "user_config_db": resolved_user,
    }


def resolve_config_path(project_root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else project_root / path


def resolve_user_config_path(project_root: Path, snapshot_dir: Path, value: str) -> Path:
    raw = resolve_config_path(project_root, value) if value else snapshot_dir
    if raw.suffix.lower() == ".xlsx":
        return raw
    return raw / "user_config.xlsx"


def validate_extra_pattern(pattern: str) -> str:
    text = str(pattern or "").strip()
    if not text:
        raise HistoryPackageError("empty pattern is not allowed", code="INVALID_PATTERN", stage="validate_pattern")
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise HistoryPackageError(f"unsafe pattern: {pattern}", code="INVALID_PATTERN", stage="validate_pattern")
    if not any(path.parts and path.parts[0] == root for root in ALLOWED_PATTERN_ROOTS):
        raise HistoryPackageError(
            f"pattern must stay under {', '.join(ALLOWED_PATTERN_ROOTS)}: {pattern}",
            code="PATH_OUTSIDE_ALLOWED_ROOT",
            stage="validate_pattern",
        )
    return text


def collect_history_sources(
    project_root: Path,
    resolved_sources: dict[str, Path | None],
    extra_patterns: tuple[str, ...],
    output: Path,
) -> tuple[list[HistorySource], list[str]]:
    warnings: list[str] = []
    candidates: list[tuple[Path, str, str]] = []
    snapshot_dir = resolved_sources.get("snapshot_dir")
    if snapshot_dir:
        candidates.extend((path, "snapshot", "analysis_snapshot_dir") for path in direct_matches(snapshot_dir, SNAPSHOT_DIR_PATTERNS))
    knowledge = resolved_sources.get("knowledge_db_path")
    if knowledge:
        candidates.extend(source_from_file_or_dir(knowledge, "knowledge_database", "indexing_knowledge_db"))
    user_config = resolved_sources.get("user_config_db")
    if user_config:
        candidates.extend(source_from_file_or_dir(user_config, "user_config", "analysis_user_config_db"))

    for pattern in DEFAULT_HISTORY_PATTERNS:
        candidates.extend((path, source_kind_for_path(path), "default") for path in sorted(project_root.glob(pattern)))
    for pattern in extra_patterns:
        safe = validate_extra_pattern(pattern)
        candidates.extend((path, source_kind_for_path(path), "extra_pattern") for path in sorted(project_root.glob(safe)))

    sources: list[HistorySource] = []
    seen_archive: dict[str, Path] = {}
    seen_real: set[Path] = set()
    for path, source_kind, logical_source in candidates:
        if is_output_path(path, output):
            continue
        source = validate_source_file(path, project_root, source_kind, logical_source)
        if source.source_path.resolve() in seen_real:
            continue
        archive_path = source.archive_path
        if archive_path in seen_archive and seen_archive[archive_path] != source.source_path:
            archive_path = disambiguate_archive_path(archive_path, source.source_path)
            source = HistorySource(source.source_path, archive_path, source.source_kind, source.is_sqlite, source.size_bytes, source.logical_source)
        seen_archive[source.archive_path] = source.source_path
        seen_real.add(source.source_path.resolve())
        if source.source_path.suffix.lower() in {".db", ".sqlite", ".sqlite3"} and not source.is_sqlite:
            warnings.append(f"{source.archive_path} has a database extension but is not a SQLite database; packaged as a regular file")
        sources.append(source)
    return sorted(sources, key=lambda item: item.archive_path), warnings


def direct_matches(root: Path, patterns: Iterable[str]) -> list[Path]:
    if not root.exists() or not root.is_dir():
        return []
    result: list[Path] = []
    for pattern in patterns:
        result.extend(sorted(root.glob(pattern)))
    return result


def source_from_file_or_dir(path: Path, source_kind: str, logical_source: str) -> list[tuple[Path, str, str]]:
    if path.exists() and path.is_dir():
        if source_kind == "user_config":
            return [(path / "user_config.xlsx", source_kind, logical_source)] if (path / "user_config.xlsx").exists() else []
        return []
    return [(path, source_kind, logical_source)] if path.exists() else []


def validate_source_file(path: Path, project_root: Path, source_kind: str, logical_source: str) -> HistorySource:
    try:
        info = path.lstat()
    except OSError as exc:
        raise HistoryPackageError(str(exc), code="ARCHIVE_WRITE_FAILED", stage="validate_source") from exc
    if stat.S_ISLNK(info.st_mode):
        raise HistoryPackageError(f"symlink source rejected: {path}", code="SYMLINK_REJECTED", stage="validate_source")
    if not stat.S_ISREG(info.st_mode):
        raise HistoryPackageError(f"unsupported source file type: {path}", code="PATH_OUTSIDE_ALLOWED_ROOT", stage="validate_source")
    archive_path = archive_name_for_source(path, project_root, logical_source)
    sqlite = is_sqlite_database(path)
    return HistorySource(path, archive_path, source_kind_for_path(path, source_kind), sqlite, info.st_size, logical_source)


def archive_name_for_source(path: Path, project_root: Path, logical_source: str) -> str:
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        namespace = {
            "analysis_snapshot_dir": "external/analysis_snapshot_dir",
            "analysis_user_config_db": "external/analysis_user_config_db",
            "indexing_knowledge_db": "external/indexing_knowledge_db",
        }.get(logical_source, "external/history")
        return f"{namespace}/{path.name}"


def disambiguate_archive_path(archive_path: str, source: Path) -> str:
    digest = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:12]
    path = Path(archive_path)
    return (path.parent / f"{path.stem}-{digest}{path.suffix}").as_posix()


def source_kind_for_path(path: Path, default: str | None = None) -> str:
    if default:
        if default == "snapshot" and path.name == "snapshots.db":
            return "snapshot_database"
        return default
    if ".zscope_knowledge" in path.parts:
        return "knowledge_database"
    if path.name == "snapshots.db":
        return "snapshot_database"
    if path.name == "user_config.xlsx":
        return "user_config"
    return "snapshot"


def is_output_path(path: Path, output: Path) -> bool:
    try:
        return path.resolve() == output.resolve()
    except OSError:
        return False


def is_sqlite_database(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError:
        return False


def enforce_limits(sources: list[HistorySource], limits: dict[str, int]) -> None:
    if len(sources) > limits["max_files"]:
        raise HistoryPackageError("source file count exceeds limit", code="SOURCE_LIMIT_EXCEEDED", stage="enforce_limits")
    total = 0
    for source in sources:
        if source.size_bytes > limits["max_single_file_bytes"]:
            raise HistoryPackageError("single source file exceeds limit", code="SOURCE_LIMIT_EXCEEDED", stage="enforce_limits")
        total += source.size_bytes
    if total > limits["max_total_bytes"]:
        raise HistoryPackageError("source total bytes exceeds limit", code="SOURCE_LIMIT_EXCEEDED", stage="enforce_limits")


def source_to_payload(source: HistorySource) -> dict[str, Any]:
    return {
        "source_kind": source.source_kind,
        "archive_path": source.archive_path,
        "size_bytes": source.size_bytes,
        "sqlite": source.is_sqlite,
    }


def write_archive(project_root: Path, sources: list[HistorySource], output: Path, warnings: list[str]) -> tuple[list[PackagedFile], Path]:
    temp_output = output.parent / f".{output.name}.tmp-{os.getpid()}-{next(tempfile._get_candidate_names())}"
    packaged: list[PackagedFile] = []
    with tempfile.TemporaryDirectory(prefix="zscope_history_staging_") as staging_s:
        staging = Path(staging_s)
        prepared: list[tuple[HistorySource, Path, str]] = []
        for source in sources:
            if source.is_sqlite:
                destination = staging / safe_staging_name(source.archive_path)
                backup = create_sqlite_backup(source.source_path, destination)
                method = "sqlite_backup"
                size = int(backup["size_bytes"])
            else:
                destination = source.source_path
                method = "copy"
                size = source.size_bytes
            digest = calculate_sha256(destination)
            packaged.append(PackagedFile(source.archive_path, source.source_kind, method, size, digest))
            prepared.append((source, destination, method))

        manifest = build_manifest(project_root, packaged, warnings)
        try:
            with tarfile.open(temp_output, "w:gz") as archive:
                for source, prepared_path, _method in prepared:
                    add_file_to_archive(archive, prepared_path, source.archive_path, mode=0o600)
                add_bytes_to_archive(
                    archive,
                    "MANIFEST.json",
                    json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
                    mode=0o644,
                )
        except tarfile.TarError as exc:
            temp_output.unlink(missing_ok=True)
            raise HistoryPackageError(str(exc), code="ARCHIVE_WRITE_FAILED", stage="write_archive") from exc
    return packaged, temp_output


def safe_staging_name(archive_path: str) -> str:
    return hashlib.sha256(archive_path.encode("utf-8")).hexdigest() + ".db"


def create_sqlite_backup(source: Path, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        source_uri = source.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(source_uri, uri=True) as source_db:
            with sqlite3.connect(destination) as target_db:
                source_db.backup(target_db)
                quick_check = target_db.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise HistoryPackageError(
                f"SQLite quick_check failed for {source}: {quick_check}",
                code="SQLITE_CHECK_FAILED",
                stage="sqlite_quick_check",
            )
    except HistoryPackageError:
        raise
    except sqlite3.Error as exc:
        raise HistoryPackageError(str(exc), code="SQLITE_BACKUP_FAILED", stage="sqlite_backup") from exc
    return {"sqlite_backup": True, "quick_check": quick_check, "size_bytes": destination.stat().st_size}


def build_manifest(project_root: Path, files: list[PackagedFile], warnings: list[str]) -> dict[str, Any]:
    return {
        "format_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "zscope_version": "unknown",
        "archive_format": "tar.gz",
        "project_name": project_root.name,
        "files": [item.__dict__ for item in sorted(files, key=lambda file: file.archive_path)],
        "warnings": warnings,
    }


def add_file_to_archive(archive: tarfile.TarFile, path: Path, arcname: str, *, mode: int) -> None:
    info = archive.gettarinfo(str(path), arcname=arcname)
    normalize_tarinfo(info, mode=mode)
    with path.open("rb") as handle:
        archive.addfile(info, handle)


def add_bytes_to_archive(archive: tarfile.TarFile, arcname: str, data: bytes, *, mode: int) -> None:
    info = tarfile.TarInfo(arcname)
    info.size = len(data)
    normalize_tarinfo(info, mode=mode)
    archive.addfile(info, io.BytesIO(data))


def normalize_tarinfo(info: tarfile.TarInfo, *, mode: int) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mode = mode
    return info


def verify_archive(path: Path, expected_files: list[str]) -> bool:
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if "MANIFEST.json" not in names:
                raise ValueError("MANIFEST.json missing")
            if len(names) != len(set(names)):
                raise ValueError("duplicate archive members")
            for member in members:
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise ValueError(f"unsafe archive member: {member.name}")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ValueError(f"unsupported archive member type: {member.name}")
            manifest_file = archive.extractfile("MANIFEST.json")
            if manifest_file is None:
                raise ValueError("MANIFEST.json not readable")
            manifest = json.load(manifest_file)
            manifest_names = [item["archive_path"] for item in manifest.get("files", [])]
            if sorted(manifest_names) != sorted(expected_files):
                raise ValueError("manifest does not match archived files")
            for name in manifest_names:
                if name not in names:
                    raise ValueError(f"manifest file missing from archive: {name}")
    except (tarfile.TarError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise HistoryPackageError(str(exc), code="ARCHIVE_VERIFY_FAILED", stage="verify_archive") from exc
    return True


def calculate_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise HistoryPackageError(str(exc), code="CHECKSUM_FAILED", stage="checksum") from exc
    return digest.hexdigest()


def error_payload(error: HistoryPackageError, *, archive_path: str = "") -> dict[str, Any]:
    return {
        "success": False,
        "error_code": error.code,
        "stage": error.stage,
        "error": str(error),
        "archive_path": archive_path,
        "partial_output_removed": True,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        payload = package_history_database(args)
    except KeyboardInterrupt:
        raise
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if payload["success"]:
            print(f"Archive: {payload['archive_path']}")
            print(f"Files: {payload.get('file_count', payload.get('source_file_count', 0))}")
        else:
            print(f"Error [{payload.get('error_code', 'ERROR')}]: {payload['error']}")
    return 0 if payload["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
