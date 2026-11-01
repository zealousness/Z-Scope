"""Native TU extraction with resumable packages and atomic public projection.

Each package retains its compile context and exact UTF-8 coordinates. Existing
query tables are a compatible projection; raw packages are never name-keyed.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import threading
from collections import Counter
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple, cast

from .indexing_identity import (
    atomic_json,
    command_identity,
    dependencies_current,
    digest_json,
    executable_identity,
    file_digest,
    load_commands,
    InputValidator,
    include_search_roots,
    include_probes_current,
)
from .indexing_runtime import admitted_workers, run_process, heartbeat
from .knowledge_db import KnowledgeDB
from .compiler_compat import POLICY_VERSION as ARGUMENT_POLICY_VERSION, POLICY_DIGEST
from .clang_derived_cache import DerivedCache, cache_key
from .clang_source_snapshot import DerivedSourceSnapshots
from .build_context import BuildContext

logger = logging.getLogger(__name__)
PROTOCOL = "zscope.clang-facts.v2"
PRODUCER = "zscope.batch.v3"
FAILURE_LOG_SAMPLES = 3
FACT_TABLES = (
    "compilation_instances",
    "compilation_facts",
    "translation_units",
    "functions",
    "type_definitions",
    "type_members",
    "call_edges",
    "macro_definitions",
    "global_variables",
    "function_symbol_refs",
    "function_program_facts",
    "function_macro_refs",
    "function_type_refs",
    "function_type_ref_state",
    "include_edges",
)


def _diagnostic_preview(text: str, limit: int = 2000) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    marker = "\n... [diagnostic truncated; see stderr log] ...\n"
    remaining = limit - len(marker)
    head = remaining * 3 // 4
    return text[:head] + marker + text[-(remaining - head) :]


class BatchExtractionError(RuntimeError):
    """Keep process diagnostics structured until the coordinator reports them."""

    def __init__(self, code: str, detail: str, metrics: Optional[Dict[str, Any]] = None):
        super().__init__(detail)
        self.code = code
        self.metrics = dict(metrics or {})


def publish_staged_database(db: KnowledgeDB, path: Path) -> None:
    """Publish compiler facts and their generation together, retaining old rows on failure."""
    connection = db._conn
    connection.execute("ATTACH DATABASE ? AS native_stage", (str(path),))
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("PRAGMA defer_foreign_keys=ON")
        for table in reversed(FACT_TABLES):
            connection.execute(f'DELETE FROM "{table}"')
        for table in FACT_TABLES:
            connection.execute(f'INSERT INTO "{table}" SELECT * FROM native_stage."{table}"')
        connection.execute("INSERT OR REPLACE INTO metadata SELECT * FROM native_stage.metadata")
        connection.commit()
        db._invalidate_callgraph_query_cache()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.execute("DETACH DATABASE native_stage")


def find_indexer(command: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    executable = shutil.which(command)
    if not executable:
        return None
    try:
        response = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
        value = json.loads(response.stdout)
        if (
            response.returncode
            or value.get("protocol") != PROTOCOL
            or value.get("position_encoding") != "utf-8"
        ):
            return None
        if (
            value.get("argument_policy_version") != ARGUMENT_POLICY_VERSION
            or value.get("argument_policy_digest") != POLICY_DIGEST
        ):
            logger.warning(
                "Clang batch indexer lacks argument policy v%d; rebuild zscope-clang-indexer: %s",
                ARGUMENT_POLICY_VERSION,
                executable,
            )
            return None
        return executable, value
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def records(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("native fact must be a JSON object")
            yield row


def _file(row: Dict[str, Any]) -> str:
    location = row.get("owner") or row.get("location") or row.get("begin") or {}
    return str(location.get("file") or "")


class BatchIndexer:
    def __init__(self, backend: Any, executable: str, capability: Dict[str, Any]):
        self._native_cache: Optional[DerivedCache] = None
        self._native_sources: Optional[DerivedSourceSnapshots] = None
        self.cancel = threading.Event()
        self.backend = backend
        self.root = Path(backend._source_path).resolve()
        self.db = backend._db
        self.executable = executable
        self.tool = {"binary": executable_identity(executable), "capability": capability}
        self.cache = Path(self.db._db_path).resolve().parent / "clang_batch_cache"
        self.memory_mb = max(256, int(os.environ.get("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "8192")))
        self.cache.mkdir(parents=True, exist_ok=True)
        owner = Path(self.db._db_path).resolve()
        self.validation_excludes = [self.cache]
        for database in (
            owner,
            owner.parent / "clang_derived_cache.sqlite3",
            owner.parent / "clang_type_refs_cache.sqlite3",
        ):
            self.validation_excludes.extend(
                Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")
            )
        self.validation_excludes.append(owner.parent / "clang_type_refs_report.json")
        self.validation_excludes.append(self.root / ".cache" / "clangd")
        # The ordinary CLI publishes these fixed report names in the project
        # root after the native input snapshot has been taken.  They are
        # Z-SCOPE outputs, not compiler inputs; allowing their first creation
        # to alter include-search membership would force an unrelated rebuild
        # on the next scan.  Keep this list exact -- arbitrary report-like
        # names must remain visible because C/C++ may include any filename.
        self.validation_excludes.extend(
            self.root / name
            for name in (
                "report.json",
                "report.md",
                "zscope_batch_report.json",
                "zscope_batch_report.md",
            )
        )
        if backend._compile_commands_path:
            self.validation_excludes.append(
                Path(backend._compile_commands_path).parent / ".cache" / "clangd"
            )
        self.validator = InputValidator(self.validation_excludes)
        self.stats: Dict[str, Any] = {
            "producer": PRODUCER,
            "compiled_tus": 0,
            "reused_tus": 0,
            "failed_tus": [],
            "fallback_files": [],
            "rpc_requests_native": 0,
            "completed_tus": 0,
            "remaining_tus": 0,
            "failure_logs_suppressed": 0,
            "argument_retries": 0,
        }

    def _jobs(self) -> List[Dict[str, Any]]:
        path = Path(self.backend._compile_commands_path)
        self.command_file_hash = file_digest(path)
        selected: Dict[str, Dict[str, Any]] = {}
        rows = load_commands(path)
        allowed_sources = {str(p.resolve()) for p in self.backend._collect_source_files()}
        for ordinal, row in enumerate(rows):
            identity = command_identity(row, path.parent)
            source = Path(identity["source"])
            if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            if str(source) not in allowed_sources:
                continue
            context = digest_json(identity)
            if context in selected:
                continue
            key = digest_json(
                {
                    "producer": PRODUCER,
                    "argument_policy_version": ARGUMENT_POLICY_VERSION,
                    "argument_policy_digest": POLICY_DIGEST,
                    "command": identity,
                    "tool": self.tool,
                    "root": str(self.root),
                    "includes": [str(p) for p in self.backend._include_paths],
                    "excludes": [str(p) for p in self.backend._exclude_paths],
                }
            )
            selected[context] = {
                **identity,
                "context": context,
                "command_identity": identity,
                "key": key,
                "ordinal": ordinal,
                "root": str(self.root),
                "includes": [str(p.resolve()) for p in self.backend._include_paths],
                "excludes": [str(p.resolve()) for p in self.backend._exclude_paths],
            }
        source_counts = Counter(job["source"] for job in selected.values())
        self.stats.update(
            command_entries=len(rows),
            selected_compile_contexts=len(selected),
            variant_sources={source: count for source, count in source_counts.items() if count > 1},
            projection_complete=all(count == 1 for count in source_counts.values()),
        )
        if file_digest(path) != self.command_file_hash:
            raise RuntimeError("compilation database changed while planning native extraction")
        return list(selected.values())

    def _cached(self, job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            manifest = json.loads((self.cache / (job["key"] + ".json")).read_text(encoding="utf-8"))
            artifact = self.cache / (job["key"] + ".jsonl")
            if (
                manifest.get("key") == job["key"]
                and manifest.get("dependencies_complete")
                and self.validator.dependencies(manifest.get("dependencies"))
                and self.validator.searches(manifest.get("search_directories"))
                and include_probes_current(
                    manifest.get("include_probes"), manifest.get("include_lookups")
                )
                and file_digest(artifact) == manifest.get("artifact_sha256")
            ):
                return {**manifest, "artifact": str(artifact), "reused": True}
        except (OSError, ValueError):
            pass
        return None

    def _extract(self, job: Dict[str, Any]) -> Dict[str, Any]:
        cached = self._cached(job)
        if cached:
            return cached
        job_path = self.cache / (job["key"] + ".job.json")
        atomic_json(job_path, job)
        directory = Path(job["directory"])
        # Build directories may be outside the scanned source root. Never
        # substitute another cwd: relative includes and response files use it.
        try:
            directory_stat = directory.stat()
        except OSError as exc:
            code = (
                "compile_directory_missing"
                if isinstance(exc, FileNotFoundError)
                else "compile_directory_unavailable"
            )
            raise BatchExtractionError(
                code,
                f"Cannot access compile_commands.json directory {str(directory)!r} "
                f"from the Z-SCOPE process: {exc}. The complete working directory "
                "must exist, including its leaf directories and symlink targets; "
                "it may be outside the source root. Restore the build inputs or "
                "regenerate the compilation database for this environment.",
                {"stage": "preflight", "errno": exc.errno, "filename": exc.filename},
            ) from exc
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise BatchExtractionError(
                "compile_directory_not_directory",
                f"compile_commands.json directory {str(directory)!r} is not a directory",
                {"stage": "preflight"},
            )
        self.validator.directories(include_search_roots(job["arguments"], directory))
        # These inputs need explicit module/PCH provenance not present in v1.
        # Auto mode retains their LSP route instead of publishing partial facts.
        if any(
            arg.startswith(("-include-pch", "-fmodule", "-include-pth")) for arg in job["arguments"]
        ):
            raise BatchExtractionError(
                "module_or_pch_context_requires_lsp", "module_or_pch_context_requires_lsp"
            )
        temporary = self.cache / (job["key"] + ".partial.jsonl")
        try:
            process = run_process(
                [self.executable, "--job", str(job_path), "--output", str(temporary)],
                cwd=directory,
                output_prefix=self.cache / job["key"],
                timeout=1800,
                memory_limit_mb=self.memory_mb,
                cancel=self.cancel,
                label="clang-batch:" + job["source"],
                log_level=logging.DEBUG,
            )
        except OSError as exc:
            raise BatchExtractionError(
                "process_start_failed",
                f"Cannot run indexer {self.executable!r} with cwd={str(directory)!r}: {exc}",
                {"errno": exc.errno, "filename": exc.filename},
            ) from exc
        footer: Dict[str, Any] = {}
        target_values: Dict[str, Any] = {}
        artifact_error = ""
        first = True
        try:
            for row in records(temporary):
                if first and row.get("protocol") != PROTOCOL:
                    raise ValueError("native artifact protocol mismatch")
                first = False
                if row.get("kind") == "program_function":
                    target_values.update(
                        {
                            key: value
                            for key, value in row.get("target_values", {}).items()
                            if key.startswith("target.")
                        }
                    )
                footer = row
            if footer.get("kind") != "complete":
                raise ValueError("native artifact missing complete footer")
        except (OSError, ValueError) as exc:
            artifact_error = f"{type(exc).__name__}: {exc}"
        adjustments = footer.get("argument_adjustments", {}) if not artifact_error else {}
        if not isinstance(adjustments, dict):
            artifact_error = "native artifact has invalid argument adjustments"
            adjustments = {}
        attempts = adjustments.get("attempts", [])
        if not isinstance(attempts, list) or any(
            not isinstance(attempt, dict) for attempt in attempts
        ):
            artifact_error = "native artifact has invalid argument attempts"
            adjustments, attempts = {}, []
        metrics = {**process.metrics, "argument_adjustments": adjustments}
        if (
            process.returncode
            or process.metrics.get("timed_out")
            or process.metrics.get("memory_exceeded")
            or process.metrics.get("cancelled")
        ):
            code = next(
                (
                    name
                    for name in ("timed_out", "memory_exceeded", "cancelled")
                    if process.metrics.get(name)
                ),
                "process_signal" if process.returncode < 0 else "process_exit",
            )
            raise BatchExtractionError(
                code,
                "native extraction failed: "
                + (_diagnostic_preview(process.stderr) or "no stderr output"),
                {**metrics, "exit_code": process.returncode},
            )
        if not artifact_error and (
            adjustments.get("policy_version") != ARGUMENT_POLICY_VERSION
            or adjustments.get("policy_digest") != POLICY_DIGEST
            or not 1 <= len(attempts) <= 2
            or any(
                not isinstance(attempt.get("error_count"), int) or attempt["error_count"] < 0
                for attempt in attempts
            )
        ):
            artifact_error = "native artifact missing supported argument policy and attempts"
        if not artifact_error and (
            not footer.get("success") or (attempts and attempts[-1].get("error_count", 0))
        ):
            artifact_error = "native artifact missing successful error-free footer"
        if artifact_error:
            raise BatchExtractionError(
                "artifact_invalid",
                artifact_error + "; " + (_diagnostic_preview(process.stderr) or "no stderr output"),
                metrics,
            )
        dependencies = footer.get("dependency_digests", {})
        if not dependencies_current(dependencies):
            raise BatchExtractionError(
                "source_or_dependency_changed_during_parse",
                "source_or_dependency_changed_during_parse",
                metrics,
            )
        complete = bool(footer.get("dependencies_complete")) and set(footer["dependencies"]) <= set(
            dependencies
        )
        probes = footer.get("include_probes")
        lookups = footer.get("include_lookups")
        complete = complete and include_probes_current(probes, lookups)
        search_roots = include_search_roots(job["arguments"], Path(job["directory"]), dependencies)
        search_roots.extend(Path(path) for path in footer.get("search_directories", []))
        searches = self.validator.directories(search_roots)
        artifact = self.cache / (job["key"] + ".jsonl")
        temporary.replace(artifact)
        return {
            "key": job["key"],
            "context": job["context"],
            "source": job["source"],
            "artifact": str(artifact),
            "artifact_sha256": file_digest(artifact),
            "dependencies": dependencies,
            "dependencies_complete": complete,
            "include_probes": probes,
            "include_lookups": lookups,
            "target_values": target_values,
            "search_directories": searches,
            "metrics": process.metrics,
            "argument_adjustments": adjustments,
            "reused": False,
        }

    def _report_failure(self, job: Dict[str, Any], exc: Exception) -> None:
        metrics = dict(exc.metrics) if isinstance(exc, BatchExtractionError) else {}
        adjustments = metrics.pop("argument_adjustments", {})
        self.stats["argument_retries"] += max(0, len(adjustments.get("attempts", [])) - 1)
        code = exc.code if isinstance(exc, BatchExtractionError) else type(exc).__name__
        reason = str(exc).strip() or type(exc).__name__
        failure = {
            "source": job["source"],
            "reason": reason,
            "code": code,
            "exception": type(exc).__name__,
            "context": job["context"],
            "directory": job["directory"],
            "indexer": self.executable,
            "job_path": str(self.cache / (job["key"] + ".job.json")),
            "stderr_path": metrics.get("stderr_path"),
            "stdout_path": metrics.get("stdout_path"),
            "metrics": metrics,
            "argument_adjustments": adjustments,
        }
        self.stats["failed_tus"].append(failure)
        reasons = self.stats.setdefault("failure_reasons", {})
        reasons[code] = reasons.get(code, 0) + 1
        # Keep representative failures visible without thousands of repeated
        # warnings. Every failure remains in the report and DEBUG log.
        level = logging.WARNING
        if reasons[code] > FAILURE_LOG_SAMPLES:
            level = logging.DEBUG
            self.stats["failure_logs_suppressed"] += 1
        logger.log(
            level,
            "[clang-batch-failed] source=%s context=%s reason=%s exit_code=%s "
            "timed_out=%s memory_exceeded=%s cancelled=%s cwd=%s job=%s stderr=%s "
            "sample=%d/%d report=%s detail=%s",
            job["source"],
            job["context"],
            code,
            metrics.get("exit_code"),
            metrics.get("timed_out", False),
            metrics.get("memory_exceeded", False),
            metrics.get("cancelled", False),
            job["directory"],
            failure["job_path"],
            failure["stderr_path"] or "-",
            reasons[code],
            FAILURE_LOG_SAMPLES,
            self.cache / "latest_run.json",
            _diagnostic_preview(reason),
        )

    def run(self) -> bool:
        started = time.monotonic()
        self.stats["complete"] = False
        logger.info(
            "[clang-batch] frontend=%s indexer=%s report=%s",
            self.backend._frontend,
            self.executable,
            self.cache / "latest_run.json",
        )
        try:
            with heartbeat("clang-batch", self.stats), self._import_session():
                ready = self._run()
                self.stats["complete"] = bool(
                    ready
                    and self.stats.get("type_refs_complete", True)
                    and self.stats.get("projection_complete", True)
                    and not self.stats["failed_tus"]
                )
                return ready
        except Exception as exc:
            self.stats["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            self.stats["wall_seconds"] = time.monotonic() - started
            atomic_json(self.cache / "latest_run.json", self.stats)
            logger.info(
                "[clang-batch] finished complete=%s phase=%s done=%d/%d compiled=%d "
                "reused=%d failed=%d suppressed=%d argument_retries=%d elapsed=%.1fs report=%s",
                self.stats["complete"],
                self.stats.get("phase", "startup"),
                self.stats["completed_tus"],
                self.stats.get("selected_compile_contexts", 0),
                self.stats["compiled_tus"],
                self.stats["reused_tus"],
                len(self.stats["failed_tus"]),
                self.stats["failure_logs_suppressed"],
                self.stats["argument_retries"],
                self.stats["wall_seconds"],
                self.cache / "latest_run.json",
            )

    def _trim_package_cache(self, key: str) -> None:
        """Discard execution temporaries, retaining the reusable TU package.

        The projected staging rows cannot replace the original facts: another
        run may select a different TU context for a shared header. Keep both
        the complete payload and its dependency manifest for warm rebuilds and
        interrupted publication recovery. Retain stderr for retry diagnostics.
        """

        for suffix in (".job.json", ".stdout.log", ".partial.jsonl"):
            candidate = self.cache / (key + suffix)
            try:
                candidate.unlink()
            except OSError:
                pass

    @contextmanager
    def _import_session(self) -> Iterator[None]:
        self._native_cache = DerivedCache()
        self._native_sources = DerivedSourceSnapshots(
            SimpleNamespace(project_root=self.root), self._native_cache, threading.local()
        )
        self.stats["import_cache"] = self._native_cache.stats
        self.stats["import_paths"] = self._native_sources.stats
        try:
            yield
        finally:
            self.stats["import_cache"] = self._native_cache.snapshot()
            self.stats["import_paths"] = self._native_sources.snapshot()
            self._native_cache.close()
            self._native_cache = None
            self._native_sources = None

    def _run(self) -> bool:
        started = time.monotonic()
        self.stats["phase"] = "input_validation"
        files = self.backend._collect_source_files()
        hashes = {str(path.resolve()): file_digest(path) for path in files}
        jobs = self._jobs()
        packages: Dict[str, Dict[str, Any]] = {}
        failed: Set[str] = set()
        workers = admitted_workers(self.backend._max_threads, len(jobs), self.memory_mb)
        self.stats.update(workers=workers, remaining_tus=len(jobs))
        if jobs and not workers:
            raise RuntimeError(
                f"insufficient memory for a batch worker reservation ({self.memory_mb} MiB)"
            )
        if jobs:
            self.stats["phase"] = "extract"
            logger.info(
                "[clang-batch] phase=extract total=%d workers=%d progress_interval=30s "
                "failure_samples_per_reason=%d",
                len(jobs),
                workers,
                FAILURE_LOG_SAMPLES,
            )
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ClangBatch") as pool:
                futures = {pool.submit(self._extract, job): job for job in jobs}
                try:
                    for future in as_completed(futures):
                        job = futures[future]
                        try:
                            package = future.result()
                            packages[job["key"]] = package
                            if not package["reused"]:
                                atomic_json(self.cache / (job["key"] + ".json"), package)
                                self.stats["argument_retries"] += max(
                                    0,
                                    len(package.get("argument_adjustments", {}).get("attempts", []))
                                    - 1,
                                )
                            self.stats["reused_tus" if package["reused"] else "compiled_tus"] += 1
                        except Exception as exc:
                            failed.add(job["key"])
                            self._report_failure(job, exc)
                        self.stats["completed_tus"] = len(packages) + len(failed)
                        self.stats["remaining_tus"] = len(jobs) - self.stats["completed_tus"]
                        logger.debug(
                            "[clang-batch] done=%d/%d compiled=%d reused=%d failed=%d",
                            len(packages) + len(failed),
                            len(jobs),
                            self.stats["compiled_tus"],
                            self.stats["reused_tus"],
                            len(failed),
                        )
                except BaseException:
                    self.cancel.set()
                    for future in futures:
                        future.cancel()
                    raise
            logger.info(
                "[clang-batch] phase=extract_complete done=%d/%d compiled=%d reused=%d failed=%d",
                self.stats["completed_tus"],
                len(jobs),
                self.stats["compiled_tus"],
                self.stats["reused_tus"],
                len(failed),
            )
        self.stats["extraction_complete"] = len(packages) == len(jobs) and not failed
        covered = (
            set().union(*(set(p["dependencies"]) for p in packages.values())) if packages else set()
        )
        failed_sources = {job["source"] for job in jobs if job["key"] in failed}
        fallback = (set(hashes) - covered) | failed_sources
        self.stats["fallback_files"] = sorted(fallback)
        if failed:
            # Make diagnostics available before potentially long LSP fallback.
            atomic_json(self.cache / "latest_run.json", self.stats)
            logger.warning(
                "[clang-batch] failed=%d/%d reasons=%s suppressed=%d next=%s fallback_files=%d report=%s",
                len(failed),
                len(jobs),
                self.stats["failure_reasons"],
                self.stats["failure_logs_suppressed"],
                "strict_batch_abort" if self.backend._frontend == "batch" else "lsp_fallback",
                len(fallback),
                self.cache / "latest_run.json",
            )
        if fallback and self.backend._frontend == "batch":
            raise RuntimeError(
                f"strict batch extraction incomplete: {len(fallback)} files require LSP"
            )
        if file_digest(Path(self.backend._compile_commands_path)) != self.command_file_hash:
            raise RuntimeError("compilation database changed during extraction")
        input_key = digest_json(
            {
                "files": hashes,
                "compilation_database": self.command_file_hash,
                "jobs": [j["key"] for j in jobs],
                "packages": {key: p["artifact_sha256"] for key, p in packages.items()},
                "producer": PRODUCER,
                "fallback": sorted(fallback),
            }
        )
        if (
            self.db.get_metadata("clang_batch_input") == input_key
            and self.db.get_metadata("clang_fact_frontend") == "batch"
            and self.backend._derived_indexes_ready_for_queries(self.db)
        ):
            self.stats["wall_seconds"] = time.monotonic() - started
            from .clang_type_state import counts

            coverage = counts(self.db)
            complete = not any(coverage[k] for k in ("pending", "in_progress", "failed"))
            self.stats.update(
                complete=complete and self.stats["projection_complete"] and not failed,
                ready_for_queries=True,
                type_refs_complete=complete,
                type_refs_functions=coverage,
                phase="complete",
                import_seconds=0.0,
            )
            self.db.set_metadata("clang_batch_stats", json.dumps(self.stats))
            logger.info(
                "[clang-batch] unchanged query-ready input; type_refs_complete=%s", complete
            )
            return True
        with tempfile.TemporaryDirectory(prefix="clang-publish-", dir=str(self.cache)) as directory:
            import_started = time.monotonic()
            self.stats["phase"] = "import"
            path = Path(directory) / "stage.sqlite3"
            with sqlite3.connect(str(path)) as target:
                self.db._conn.backup(target)
            stage = KnowledgeDB(str(path))
            setattr(stage, "_derived_cache_owner_path", self.db._db_path)
            try:
                stage._conn.execute("PRAGMA temp_store=FILE")
                stage._conn.execute(
                    "CREATE TEMP TABLE native_facts (context TEXT, sequence INTEGER, kind TEXT, file TEXT, data TEXT)"
                )
                stage._conn.execute("CREATE INDEX native_fact_file ON native_facts(file,kind)")
                projection: Dict[str, str] = {}
                projected_sources: Set[str] = set()
                for job in jobs:
                    selected_package = packages.get(job["key"])
                    if selected_package:
                        for dependency in selected_package["dependencies"]:
                            projection.setdefault(dependency, job["key"])
                        # A main file always uses its own selected command.
                        # The old name/file tables remain a navigation projection.
                        # All instances live in compilation_facts; proof queries
                        # require an explicit context when this projection is lossy.
                        if job["source"] not in projected_sources:
                            projection[job["source"]] = job["key"]
                            projected_sources.add(job["source"])
                for key, package in packages.items():
                    batch = []
                    for sequence, row in enumerate(records(Path(package["artifact"]))):
                        batch.append(
                            (key, sequence, row.get("kind", ""), _file(row), json.dumps(row))
                        )
                        if len(batch) >= 1000:
                            stage._conn.executemany(
                                "INSERT INTO native_facts VALUES (?,?,?,?,?)", batch
                            )
                            batch.clear()
                    if batch:
                        stage._conn.executemany(
                            "INSERT INTO native_facts VALUES (?,?,?,?,?)", batch
                        )
                stage._conn.execute(
                    "CREATE TEMP TABLE native_projection(file TEXT PRIMARY KEY, context TEXT)"
                )
                stage._conn.executemany(
                    "INSERT INTO native_projection VALUES (?,?)", projection.items()
                )
                stage._conn.commit()
                self._publish_base(stage, hashes, fallback)
                self._publish_references(stage, fallback)
                self._publish_program_facts(stage)
                self._publish_compilation_instances(stage, jobs, packages)
                from .clang_type_state import initialize_states, counts

                contexts = {
                    self._relative(p): digest_json(
                        [
                            p,
                            [job["context"] for job in jobs if job["source"] == p]
                            or [job["context"] for job in jobs],
                        ]
                    )
                    for p in fallback
                }
                initialize_states(stage, digest_json([input_key, "function-types-v7"]), contexts)
                coverage = counts(stage)
                type_complete = not any(coverage[k] for k in ("pending", "in_progress", "failed"))
                self.stats.update(
                    ready_for_queries=True,
                    type_refs_complete=type_complete,
                    type_refs_functions=coverage,
                    complete=type_complete and self.stats["projection_complete"] and not failed,
                )
                for path_value, expected in hashes.items():
                    if file_digest(Path(path_value)) != expected:
                        raise RuntimeError("source changed before publication: " + path_value)
                if self._native_sources is not None:
                    self._native_sources.validate_all()
                if file_digest(Path(self.backend._compile_commands_path)) != self.command_file_hash:
                    raise RuntimeError("compilation database changed before publication")
                final_validator = InputValidator(self.validation_excludes)
                if any(
                    not final_validator.dependencies(p["dependencies"])
                    or not final_validator.searches(p["search_directories"])
                    or (
                        p["dependencies_complete"]
                        and not include_probes_current(
                            p.get("include_probes"), p.get("include_lookups")
                        )
                    )
                    for p in packages.values()
                ):
                    raise RuntimeError("dependency changed before publication")
                self.stats["wall_seconds"] = time.monotonic() - started
                self.stats["import_seconds"] = time.monotonic() - import_started
                stage.set_metadata("clang_batch_input", input_key)
                stage.set_metadata("clang_batch_stats", json.dumps(self.stats))
                stage.set_metadata("clang_fact_frontend", "batch")
                self.backend._mark_base_indexes_current(stage)
                receipt = getattr(self.backend, "_compile_preparation", None)
                if receipt is not None:
                    receipt.validate()
                stage.commit()
                self._commit(stage, path)
                self.stats["import_seconds"] = time.monotonic() - import_started
                self.stats["wall_seconds"] = time.monotonic() - started
                self.stats["phase"] = "complete"
            finally:
                stage.close()
        return True

    def _relative(self, value: str) -> str:
        if not value:
            return ""
        try:
            snapshots = getattr(self, "_native_sources", None)
            path = Path(value)
            absolute = (
                Path(snapshots.path(path if path.is_absolute() else Path.cwd() / path)["absolute"])
                if snapshots is not None
                else path.resolve()
            )
            return absolute.relative_to(self.root).as_posix()
        except ValueError:
            return Path(value).as_posix()

    def _native_binding(
        self, stage: KnowledgeDB, kind: str, target: Dict[str, Any], types: Dict[Any, Any]
    ) -> Dict[str, Any]:
        usr, name = target.get("usr", ""), target.get("qualified_name") or target["name"]
        if kind == "type" and target.get("is_system_header"):
            record = types.get(
                (
                    name,
                    target.get("type_kind"),
                    self._relative(target["location"]["file"]),
                    target["location"]["line"],
                )
            )
            if record:
                return {
                    "id": record["id"],
                    "index_name": KnowledgeDB.type_index_name(record),
                    "reason": "",
                }

        def compute() -> Dict[str, Any]:
            self.stats["identity_queries"] = self.stats.get("identity_queries", 0) + 1
            definitions, matches = set(), {}
            seen = False
            for row in stage._conn.execute(
                "SELECT data FROM native_identities WHERE usr=? AND kind=?", (usr, kind)
            ):
                seen = True
                declaration = json.loads(row[0])
                if kind == "global":
                    if declaration["definition_kind"] == "definition":
                        definitions.add(self._relative(declaration["location"]["file"]))
                else:
                    if (
                        target.get("definition_hash")
                        and declaration["target"].get("definition_hash")
                        != target["definition_hash"]
                    ):
                        continue
                    begin = declaration["begin"]
                    candidate = types.get(
                        (
                            name,
                            declaration["type_kind"],
                            self._relative(begin["file"]),
                            begin["line"],
                        )
                    )
                    if candidate:
                        matches[candidate["id"]] = candidate
            if kind == "global":
                return {
                    "_volatile": True,
                    "target_file": next(iter(definitions)) if len(definitions) == 1 else None,
                    "reason": (
                        "multiple_definitions_for_usr"
                        if len(definitions) > 1
                        else "global_outside_base" if not seen else ""
                    ),
                }
            record = next(iter(matches.values())) if len(matches) == 1 else None
            return {
                "_volatile": True,
                "id": record["id"] if record else None,
                "index_name": KnowledgeDB.type_index_name(record) if record else "",
                "reason": (
                    "" if record else "type_context_not_projected" if seen else "type_not_in_base"
                ),
            }

        cache = getattr(self, "_native_cache", None)
        if cache is None:
            return compute()
        return cast(
            Dict[str, Any],
            cache.compute(
                "native_binding",
                cache_key([kind, usr, name, target.get("definition_hash")]),
                compute,
            ),
        )

    def _rows(
        self, stage: KnowledgeDB, file: Optional[str] = None, kinds: Optional[Iterable[str]] = None
    ) -> Iterator[Dict[str, Any]]:
        terms, arguments = [], []
        if file is not None:
            terms.append("file=?")
            arguments.append(file)
        if kinds:
            values = list(kinds)
            terms.append("kind IN (" + ",".join("?" for _ in values) + ")")
            arguments.extend(values)
        terms.append(
            "context=(SELECT context FROM native_projection WHERE native_projection.file=native_facts.file)"
        )
        query = "SELECT data FROM native_facts" + (" WHERE " + " AND ".join(terms) if terms else "")
        query += " ORDER BY context,sequence"
        for row in stage._conn.execute(query, arguments):
            yield json.loads(row[0])

    def _publish_base(self, stage: KnowledgeDB, hashes: Dict[str, str], fallback: Set[str]) -> None:
        from .clang_extractor import ClangExtractor

        definitions: Dict[str, Dict[str, Any]] = {}
        for record in self._rows(stage, kinds=("function",)):
            if not record.get("is_declaration") and record.get("usr"):
                definitions[str(record["usr"])] = record
        existing: Dict[str, List[Dict[str, Any]]] = {}
        for row in stage.get_all_tus():
            source = str((self.root / row["file_path"]).resolve())
            existing.setdefault(source, []).append(row)
        for source, rows in existing.items():
            # File-owned query rows use project-relative paths. Older batch
            # versions and clangd fallback registered absolute TU paths.  An
            # interrupted/hot run can therefore leave both spellings for the
            # same source.  Coalesce those identities before normalization so
            # updating the absolute row cannot collide with the relative row's
            # UNIQUE(file_path) key.
            relative = self._relative(source)
            if source not in hashes:
                for row in rows:
                    stage.delete_tu(int(row["id"]), commit=False)
                continue
            keeper = next(
                (row for row in rows if str(row.get("file_path") or "") == relative),
                min(rows, key=lambda row: int(row["id"])),
            )
            duplicates = [row for row in rows if int(row["id"]) != int(keeper["id"])]
            for row in duplicates:
                stage.delete_tu(int(row["id"]), commit=False)
            if duplicates:
                # Duplicate cleanup removes file-owned/path-keyed projections;
                # force the survivor through the normal exact native republish.
                stage._conn.execute(
                    "UPDATE translation_units SET status='pending' WHERE id=?",
                    (keeper["id"],),
                )
            if keeper["file_path"] != relative:
                stage._conn.execute(
                    "UPDATE translation_units SET file_path=? WHERE id=?",
                    (relative, keeper["id"]),
                )
        for source, digest in hashes.items():
            if source in fallback:
                continue
            relative = self._relative(source)
            values: Dict[str, Any] = {
                key: []
                for key in (
                    "func_rows",
                    "call_rows",
                    "type_rows",
                    "global_rows",
                    "macro_rows",
                    "include_rows",
                )
            }
            tu_id, changed = stage.register_tu_hash(relative, digest)
            seen: Set[str] = set()
            for row in self._rows(
                stage,
                source,
                ("function", "type", "global", "macro", "include", "call", "type_reference"),
            ):
                key = digest_json(row)
                if key in seen:
                    continue
                seen.add(key)
                kind = row["kind"]
                if kind == "function":
                    values["func_rows"].append(
                        (
                            row["name"],
                            relative,
                            row["begin"]["line"],
                            row["end"]["line"],
                            " ".join(row["signature"].strip().rstrip(";").split()),
                            int(row["is_static"]),
                            int(row["is_inline"]),
                            int(row["is_declaration"]),
                            tu_id,
                        )
                    )
                elif kind == "type_reference" and row["target"].get("is_system_header"):
                    target = row["target"]
                    if target.get("type_definition"):
                        values["type_rows"].append(
                            {
                                "name": target.get("qualified_name") or target["name"],
                                "kind": target["type_kind"],
                                "file_path": self._relative(target["location"]["file"]),
                                "start_line": target["location"]["line"],
                                "end_line": target["location"]["line"],
                                "full_definition": target["type_definition"],
                                "members": [],
                            }
                        )
                elif kind == "type":
                    values["type_rows"].append(
                        {
                            "name": row["target"]["qualified_name"],
                            "kind": row["type_kind"],
                            "file_path": relative,
                            "start_line": row["begin"]["line"],
                            "end_line": row["end"]["line"],
                            "full_definition": row["definition"],
                            "members": [
                                (m["name"], m["type"], i) for i, m in enumerate(row["members"])
                            ],
                        }
                    )
                elif kind == "global":
                    values["global_rows"].append(
                        {
                            "name": row["target"]["qualified_name"],
                            "detail": row["type"],
                            "file_path": relative,
                            "line": row["location"]["line"],
                            "metadata": {
                                key: row[key]
                                for key in (
                                    "is_extern",
                                    "storage_class",
                                    "qualifiers",
                                    "initializer",
                                    "definition_kind",
                                )
                            },
                        }
                    )
                elif kind == "macro":
                    values["macro_rows"].append(
                        (
                            row["name"],
                            relative,
                            row["begin"]["line"],
                            row["end"]["line"],
                            f'{row["name"]}@{relative}:{row["begin"]["line"]}-{row["end"]["line"]}',
                            row["definition"],
                            int(row["is_function_like"]),
                        )
                    )
                elif kind == "include":
                    values["include_rows"].append(
                        (
                            relative,
                            self._relative(row["target_file"]),
                            row["location"]["line"],
                            int(row["is_system"]),
                        )
                    )
                elif kind == "call":
                    target = row["target"]
                    definition = definitions.get(str(target.get("usr") or ""))
                    resolved_file = (
                        definition["begin"]["file"] if definition else target["location"]["file"]
                    )
                    resolved_signature = (
                        definition["signature"] if definition else target.get("signature", "")
                    )
                    values["call_rows"].append(
                        (
                            row["owner"]["name"],
                            relative,
                            target["qualified_name"],
                            self._relative(resolved_file),
                            row["location"]["line"],
                            row.get("call_type", "direct"),
                            (
                                "function"
                                if definition
                                else (
                                    "system_function"
                                    if target.get("is_system_header")
                                    else (
                                        "external_function"
                                        if not target.get("has_definition", True)
                                        else row.get("callee_kind", "function")
                                    )
                                )
                            ),
                            resolved_signature,
                        )
                    )
            fingerprint = digest_json([PRODUCER, values])
            if changed or stage.get_metadata("clang_batch_base:" + relative) != fingerprint:
                ClangExtractor._publish_tu_facts(stage, tu_id, **values)
                stage.mark_tu_indexed(tu_id)
                stage.set_metadata("clang_batch_base:" + relative, fingerprint)
        if fallback:
            if not self.backend._ensure_extractor():
                raise RuntimeError("clangd fallback could not start")
            seed = getattr(self.backend._extractor, "seed_project_file_index", None)
            if callable(seed):
                seed([Path(p) for p in hashes])
            stats = self.backend._extractor.run_batch_extraction(
                [Path(p) for p in sorted(fallback)], stage, batch_size=self.backend._batch_size
            )
            self.stats["fallback_base_stats"] = stats
            if stats.get("failed"):
                raise RuntimeError("clangd fallback base facts incomplete")

    def _publish_compilation_instances(
        self,
        stage: KnowledgeDB,
        jobs: List[Dict[str, Any]],
        packages: Dict[str, Dict[str, Any]],
    ) -> None:
        """Publish the exact-context store in the same transaction as the projection."""
        stage._conn.execute("DELETE FROM compilation_facts")
        stage._conn.execute("DELETE FROM compilation_instances")
        failures = {row["context"]: row for row in self.stats["failed_tus"]}
        for job in jobs:
            package = packages.get(job["key"])
            dependencies = (
                package["dependencies"]
                if package
                else {job["source"]: file_digest(Path(job["source"]))}
            )
            context = BuildContext.create(
                job["command_identity"],
                tool=self.tool,
                dependencies=dependencies,
                dependencies_complete=bool(package and package["dependencies_complete"]),
                target=package.get("target_values", {}) if package else {},
                include_probes=package.get("include_probes") if package else None,
                include_lookups=package.get("include_lookups") if package else None,
            )
            manifest = context.to_dict()
            manifest.update(
                source=self._relative(job["source"]),
                status="indexed" if package else "failed",
                failure=failures.get(job["context"]),
                search_directories=package.get("search_directories", {}) if package else {},
                search_excludes=[str(path) for path in self.validation_excludes],
                compilation_database={
                    "path": str(Path(self.backend._compile_commands_path).resolve()),
                    "sha256": self.command_file_hash,
                },
            )
            stage._conn.execute(
                "INSERT INTO compilation_instances VALUES (?,?,?,?)",
                (context.context_id, context.command_id, manifest["source"], json.dumps(manifest)),
            )
            if not package:
                continue
            rows = []
            for sequence, row in enumerate(records(Path(package["artifact"]))):
                owner = row.get("owner") or {}
                target = row.get("target") or {}
                symbol = owner.get("name") or row.get("name") or target.get("qualified_name") or ""
                # Raw compiler identities remain intact. The surrounding context
                # supplies their namespace, including file-local USRs in headers.
                rows.append(
                    (
                        context.context_id,
                        sequence,
                        row.get("kind", ""),
                        self._relative(_file(row)),
                        symbol,
                        json.dumps(row),
                    )
                )
                if len(rows) >= 1000:
                    stage._conn.executemany(
                        "INSERT INTO compilation_facts VALUES (?,?,?,?,?,?)", rows
                    )
                    rows.clear()
            stage._conn.executemany("INSERT INTO compilation_facts VALUES (?,?,?,?,?,?)", rows)

    def _publish_program_facts(self, stage: KnowledgeDB) -> None:
        # This stage contains the complete selected native projection. Replace
        # it as a generation: changed/removed functions and newly unsupported
        # fallback files must not inherit compiler evidence from an older TU.
        stage._conn.execute("DELETE FROM function_program_facts")
        for row in self._rows(stage, kinds=("program_function", "program_access")):
            owner = row.get("owner") or {}
            location = row.get("location") or {}
            if not owner.get("name"):
                continue
            # Exact compiler owner and location, never a bare symbol name.
            owner_file = owner.get("file") or location.get("file")
            stage._conn.execute(
                "INSERT OR REPLACE INTO function_program_facts VALUES(?,?,?,?,?,?)",
                (
                    owner["name"],
                    self._relative(str(owner_file)),
                    int(owner.get("line") or 0),
                    row["kind"],
                    digest_json(row),
                    json.dumps(row),
                ),
            )

    def _publish_references(self, stage: KnowledgeDB, fallback: Set[str]) -> None:
        symbol_index, type_index = (
            self.backend.FUNCTION_SYMBOL_CONTEXT_INDEX,
            self.backend.FUNCTION_TYPE_REFS_INDEX,
        )
        versions = {
            symbol_index: self.backend.SYMBOL_CONTEXT_EXTRACTOR_VERSION,
            type_index: self.backend.FUNCTION_TYPE_REF_EXTRACTOR_VERSION,
        }
        for name, version in versions.items():
            stage.begin_derived_index_rebuild(name, version)
            stage.prepare_derived_index_staging(name)
        if fallback:
            logger.info(
                "[clang-batch] fallback phase=symbol-context files=%d type_refs=deferred",
                len(fallback),
            )
            result = self.backend._extractor.rebuild_function_symbol_refs(
                stage, use_staging=True, only_files={self._relative(p) for p in fallback}
            )
            get_stats = getattr(self.backend._extractor, "get_last_derived_stats", None)
            symbol_stats = get_stats(symbol_index) if callable(get_stats) else {}
            errors = result.get("errors") if isinstance(result, dict) else None
            self.stats["fallback_derived_stats"] = {
                "symbol_context": symbol_stats,
                "result": result,
            }
            if errors or symbol_stats.get("_incomplete"):
                raise RuntimeError(
                    "clangd fallback derived facts incomplete: " + str(errors or symbol_stats)
                )
            get_stats = getattr(self.backend._extractor, "get_last_derived_stats", None)
            if callable(get_stats):
                self.stats["fallback_rpc_stats"] = {name: get_stats(name) for name in versions}
        functions = {
            (row["name"], row["file_path"], row["start_line"]): row["id"]
            for row in stage._conn.execute("SELECT id,name,file_path,start_line FROM functions")
        }
        macros = {
            (row["name"], row["file_path"], row["start_line"]): row["id"]
            for row in stage._conn.execute(
                "SELECT id,name,file_path,start_line FROM macro_definitions"
            )
        }
        types = {
            (row["name"], row["kind"], row["file_path"], row["start_line"]): dict(row)
            for row in stage._conn.execute("SELECT * FROM type_definitions")
        }
        # Compiler identity, never (file, name), connects declarations across TUs.
        stage._conn.execute("CREATE TEMP TABLE native_identities(usr TEXT, kind TEXT, data TEXT)")
        stage._conn.execute("CREATE INDEX native_identity_usr ON native_identities(usr,kind)")
        identities = []
        for declaration in self._rows(stage, kinds=("global", "type")):
            identity = declaration["target"]["usr"]
            if identity:
                identities.append((identity, declaration["kind"], json.dumps(declaration)))
            if len(identities) >= 1000:
                stage._conn.executemany("INSERT INTO native_identities VALUES (?,?,?)", identities)
                identities.clear()
        stage._conn.executemany("INSERT INTO native_identities VALUES (?,?,?)", identities)
        symbols, macro_refs, type_refs = [], [], []
        reasons: Counter[str] = Counter()
        for row in self._rows(
            stage, kinds=("symbol_reference", "type_reference", "macro_reference")
        ):
            source = row["owner"]["file"]
            if source in fallback:
                continue
            owner, target, use = row["owner"], row["target"], row["location"]
            relative = self._relative(source)
            function_id = functions.get((owner["name"], relative, owner["line"]))
            if function_id is None:
                reasons["function_not_in_base"] += 1
                continue
            target_file = self._relative(target["location"]["file"])
            name = target.get("qualified_name") or target["name"]
            if row["kind"] == "symbol_reference":
                binding = self._native_binding(stage, "global", target, types)
                if binding["reason"]:
                    reasons[binding["reason"]] += 1
                    continue
                if binding["target_file"] is not None:
                    target_file = binding["target_file"]
                symbols.append(
                    (
                        owner["name"],
                        relative,
                        name,
                        "global",
                        target_file,
                        use["line"],
                        row["access_kind"],
                    )
                )
            elif row["kind"] == "macro_reference":
                macro_id = macros.get((name, target_file, target["location"]["line"]))
                if macro_id is not None:
                    macro_refs.append((function_id, macro_id, use["line"]))
                    symbols.append(
                        (owner["name"], relative, name, "macro", target_file, use["line"], "read")
                    )
                else:
                    reasons["macro_not_in_base"] += 1
            else:
                binding = self._native_binding(stage, "type", target, types)
                reason = binding["reason"]
                if reason:
                    reasons[reason] += 1
                type_refs.append(
                    (
                        function_id,
                        binding["id"],
                        binding["index_name"],
                        name,
                        relative,
                        use["line"],
                        row["reference_kind"],
                        reason,
                    )
                )
            if len(symbols) + len(macro_refs) + len(type_refs) >= 1000:
                stage.stage_function_symbol_refs_batch(symbols)
                stage.stage_function_macro_refs_batch(macro_refs)
                stage.stage_function_type_refs_batch(type_refs)
                symbols.clear()
                macro_refs.clear()
                type_refs.clear()
        stage.stage_function_symbol_refs_batch(symbols)
        stage.stage_function_macro_refs_batch(macro_refs)
        stage.stage_function_type_refs_batch(type_refs)
        self.stats["unresolved_reasons"] = dict(reasons)
        for name, version in versions.items():
            stage.finalize_derived_index_rebuild(name, version, self.stats)

    def _commit(self, stage: KnowledgeDB, path: Path) -> None:
        publish_staged_database(self.db, path)
