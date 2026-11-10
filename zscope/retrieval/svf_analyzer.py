"""Run SVF tools and import their results into KnowledgeDB."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Mapping, cast

from ..config.function_entry import FunctionEntry
from .bitcode_scope import BitcodeScopeConfig
from .build_llvm import BitcodeBuilder
from .knowledge_db import KnowledgeDB
from .svf_parser import SvfOutputMapper
from .svf_runner import SvfResult, SvfRunner

logger = logging.getLogger(__name__)


_SABER_HEAP_PER_WORKER_MB = 8192


class SvfAnalyzer:
    """Build bitcode, run SVF, and write indirect-call/Saber data."""

    MATERIALIZATION_SCHEMA_VERSION = 1
    MATERIALIZATION_STATE_KEY = "svf_db_materialization"

    def __init__(
        self,
        db: KnowledgeDB,
        svf_bin_dir: str = "",
        gclang_path: str = "gclang",
        get_bc_path: str = "get-bc",
        llvm_link_path: str = "llvm-link",
        heap_limit_mb: int = 32768,
        timeout: int = 1800,
        scope: str = "auto",
        entry_depth: int = 4,
        max_selected_tus: int = 200,
        fallback: str = "full",
        always_include: Optional[List[str]] = None,
        symbol_closure: bool = True,
        exclusive_pools: Optional[List[Dict[str, Any]]] = None,
        shared_pools: Optional[List[Dict[str, Any]]] = None,
        parallel_workers: int = 1,
    ):
        self._db = db
        self._svf_bin_dir = svf_bin_dir
        self._gclang = gclang_path
        self._get_bc = get_bc_path
        self._llvm_link = llvm_link_path
        self._heap_limit = heap_limit_mb
        self._timeout = timeout
        self._scope_config = BitcodeScopeConfig(
            mode=scope,
            entry_depth=entry_depth,
            max_selected_tus=max_selected_tus,
            fallback=fallback,
            always_include=list(always_include or []),
            symbol_closure=symbol_closure,
            exclusive_pools=list(exclusive_pools or []),
            shared_pools=list(shared_pools or []),
        )
        self._parallel_workers = max(1, int(parallel_workers or 1))
        self._project_root: Optional[Path] = None

    def run(
        self,
        source_path: Path,
        project_root: Path,
        compile_commands_path: Optional[Path] = None,
        svf_groups_config: str = "",
        entry_functions: Optional[Sequence[Any]] = None,
    ) -> bool:
        if not compile_commands_path:
            logger.warning("No compile_commands_path, skipping SVF")
            return True

        self._project_root = Path(project_root)

        try:
            groups = self._load_groups_config(project_root, svf_groups_config)
            normalized_entries = self._normalize_entry_functions(entry_functions)
            scope_entries = list(entry_functions or normalized_entries)
            cache_fingerprint = self._compute_aggregate_hash(
                compile_commands_path,
                groups,
                self._cache_config(),
                normalized_entries,
            )
            legacy_cache_fingerprint = self._compute_aggregate_hash(
                compile_commands_path,
                groups,
                self._cache_config(),
                normalized_entries,
                sort_entry_functions=False,
            )
            old_hash = self._db.get_svf_hash()
            materialization_current = self._materialization_current(project_root)
            if (
                cache_fingerprint
                and old_hash
                in {
                    cache_fingerprint,
                    legacy_cache_fingerprint,
                }
                and materialization_current
            ):
                if old_hash == legacy_cache_fingerprint and old_hash != cache_fingerprint:
                    self._db.set_svf_hash(cache_fingerprint)
                logger.info("SVF incremental: cache fingerprint unchanged; reusing cached data")
                return True
            if cache_fingerprint and old_hash in {
                cache_fingerprint,
                legacy_cache_fingerprint,
            }:
                logger.info(
                    "SVF incremental: source cache hit but DB materialization is stale; "
                    "event=materialization_recovery"
                )
            if old_hash:
                logger.info(
                    "SVF incremental: cache miss (old=%s, new=%s, entries=%d)",
                    old_hash[:12],
                    (cache_fingerprint or "")[:12],
                    len(normalized_entries),
                )
            else:
                logger.info(
                    "SVF incremental: no previous cache fingerprint; building SVF data"
                )

            builder = BitcodeBuilder(
                source_root=source_path,
                compile_commands_path=compile_commands_path,
                gclang_path=self._gclang,
                get_bc_path=self._get_bc,
                llvm_link_path=self._llvm_link,
                timeout=self._timeout,
            )
            only_sources = None
            if self._lazy_bitcode_enabled():
                try:
                    only_sources = builder.plan_required_sources(
                        groups=groups,
                        scope_config=self._scope_config,
                        entry_functions=scope_entries,
                        knowledge_db=self._db,
                        project_root=project_root,
                        auto_entry_clusters=self._scope_config.mode != "full"
                        and bool(scope_entries),
                    )
                except Exception as exc:
                    logger.warning("Lazy bitcode planning failed; using the full build: %s", exc)
            bc_paths = self._build_bitcode(
                builder,
                groups=groups,
                scope_entries=scope_entries,
                project_root=project_root,
                explicit_groups_config=bool(svf_groups_config),
                only_sources=only_sources,
            )
            failed_tus = list(getattr(builder, "failed_tus", []))
            bitcode_complete = not failed_tus
            if failed_tus:
                logger.warning(
                    "Bitcode build incomplete: %d translation unit(s) failed; "
                    "SVF source cache will not be marked complete",
                    len(failed_tus),
                )

            if not bc_paths:
                logger.warning("Bitcode build failed or no bitcode generated; SVF skipped")
                return True

            artifact_fingerprint = self._compute_artifact_hash(
                bc_paths,
                groups,
                self._cache_config(),
                normalized_entries,
            )
            old_artifact_hash = self._db.get_metadata("svf_artifact_hash")
            if (
                artifact_fingerprint
                and artifact_fingerprint == old_artifact_hash
                and materialization_current
            ):
                logger.info(
                    "SVF incremental: merged bitcode fingerprint unchanged; "
                    "reusing cached SVF data"
                )
                if cache_fingerprint and bitcode_complete:
                    self._db.set_svf_hash(cache_fingerprint)
                elif not bitcode_complete:
                    logger.info(
                        "SVF incremental: bitcode build is incomplete; "
                        "leaving source cache fingerprint unset"
                    )
                return True
            reused_linked_groups = set(getattr(builder, "reused_linked_groups", set()))
            if (
                old_hash
                and bc_paths
                and set(bc_paths.keys()) == reused_linked_groups
                and materialization_current
            ):
                logger.info(
                    "SVF incremental: merged bitcode reused for all groups; "
                    "refreshing cache fingerprint without rerunning SVF"
                )
                if cache_fingerprint and bitcode_complete:
                    self._db.set_svf_hash(cache_fingerprint)
                elif not bitcode_complete:
                    logger.info(
                        "SVF incremental: bitcode build is incomplete; "
                        "leaving source cache fingerprint unset"
                    )
                if artifact_fingerprint:
                    self._db.set_metadata("svf_artifact_hash", artifact_fingerprint)
                return True

            runner = SvfRunner(
                svf_bin_dir=self._svf_bin_dir,
                heap_limit_mb=self._heap_limit,
                timeout=self._timeout,
            )

            had_timeout = self._run_split_svf(runner, bc_paths, project_root)

            if had_timeout:
                logger.warning(
                    "SVF analysis or materialization failed; cache fingerprint will not be updated"
                )
                return False

            self._mark_materialization_complete(bc_paths)

            if cache_fingerprint and bitcode_complete:
                self._db.set_svf_hash(cache_fingerprint)
            elif not bitcode_complete:
                logger.warning(
                    "SVF analysis used partial bitcode; cache fingerprint will not be updated "
                    "so failed translation unit(s) are retried next run"
                )
            if artifact_fingerprint:
                self._db.set_metadata("svf_artifact_hash", artifact_fingerprint)
            return True
        except Exception as exc:
            logger.error("SVF analysis failed: %s", exc)
            return False

    def _build_bitcode(
        self,
        builder: Any,
        *,
        groups: Dict[str, List[str]],
        scope_entries: Sequence[Any],
        project_root: Path,
        explicit_groups_config: bool = False,
        only_sources: Optional[Set[str]] = None,
    ) -> Dict[str, Path]:
        """Call BitcodeBuilder with scope kwargs when the implementation supports them."""
        params: Mapping[str, inspect.Parameter]
        try:
            params = inspect.signature(builder.build).parameters
        except (TypeError, ValueError):
            params = {}
        supports_scope_kwargs = "scope_config" in params or any(
            param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values()
        )
        if not supports_scope_kwargs:
            return cast(Dict[str, Path], builder.build(groups=groups))
        build_kwargs: Dict[str, Any] = dict(
            groups=groups,
            scope_config=self._scope_config,
            entry_functions=scope_entries,
            knowledge_db=self._db,
            project_root=project_root,
            auto_entry_clusters=(self._scope_config.mode != "full" and bool(scope_entries)),
            saber_groups=True,
        )
        supports_only_sources = "only_sources" in params or any(
            param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values()
        )
        if only_sources is not None and supports_only_sources:
            build_kwargs["only_sources"] = only_sources
        return cast(Dict[str, Path], builder.build(**build_kwargs))

    def _run_split_svf(
        self,
        runner: Any,
        bc_paths: Dict[str, Path],
        project_root: Path,
    ) -> bool:
        wpa_paths = {
            name: path for name, path in bc_paths.items() if not self._is_saber_group(name)
        }
        saber_paths = {
            name: path for name, path in bc_paths.items() if self._is_saber_group(name)
        }
        if hasattr(self._db, "purge_svf_data_except"):
            self._db.purge_svf_data_except(set(wpa_paths) | set(saber_paths))

        had_timeout = self._run_wpa_groups(runner, wpa_paths, project_root)
        if self._run_saber_groups(runner, saber_paths, project_root):
            had_timeout = True
        return had_timeout

    def _run_wpa_groups(
        self,
        runner: Any,
        wpa_paths: Dict[str, Path],
        project_root: Path,
    ) -> bool:
        if not wpa_paths:
            return False
        max_workers = max(1, min(self._parallel_workers, len(wpa_paths)))
        logger.info("Running %d WPA group(s) with %d worker(s)", len(wpa_paths), max_workers)
        had_timeout = False
        pending_paths: Dict[str, Path] = {}
        for group_name, bc_path in wpa_paths.items():
            fingerprint = self._tool_artifact_fingerprint("ander", group_name, bc_path)
            status = self._load_tool_status("ander", group_name)
            artifact = self._validated_replay_artifact(
                "ander", group_name, fingerprint, status, project_root
            )
            if artifact and self._materialization_marker_valid(
                "ander", group_name, fingerprint, artifact[1]
            ):
                logger.info(
                    "SVF resume: event=cache_skip tool=ander group=%s",
                    group_name,
                )
                continue
            if artifact:
                artifact_path, artifact_hash, artifact_relpath = artifact
                if self._materialize_group(
                    "ander",
                    group_name,
                    fingerprint,
                    artifact_path,
                    artifact_hash,
                    artifact_relpath,
                ):
                    logger.info(
                        "SVF resume: event=artifact_reimport tool=ander group=%s",
                        group_name,
                    )
                    continue
                logger.warning(
                    "SVF resume: event=recovery_failed tool=ander group=%s; rerunning tool",
                    group_name,
                )
            pending_paths[group_name] = bc_path
        if not pending_paths:
            return False
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="zscope-wpa") as executor:
            futures = {
                executor.submit(self._run_one_wpa_group, runner, group_name, bc_path, project_root): (
                    group_name,
                    bc_path,
                )
                for group_name, bc_path in pending_paths.items()
            }
            for future in as_completed(futures):
                group_name, _bc_path = futures[future]
                fingerprint = self._tool_artifact_fingerprint("ander", group_name, _bc_path)
                try:
                    result = future.result()
                except Exception as exc:
                    logger.warning("WPA group '%s' failed: %s", group_name, exc)
                    self._write_tool_status(
                        "ander",
                        group_name,
                        fingerprint,
                        status="failed",
                        timed_out=False,
                    )
                    had_timeout = True
                    continue
                if result.timed_out:
                    self._write_tool_status(
                        "ander",
                        group_name,
                        fingerprint,
                        status="timed_out",
                        timed_out=True,
                        result=result,
                    )
                    had_timeout = True
                    continue
                output_file = Path(result.output_file) if result.output_file else None
                if not result.success or not output_file or not output_file.is_file():
                    self._write_tool_status(
                        "ander",
                        group_name,
                        fingerprint,
                        status="failed",
                        timed_out=False,
                        result=result,
                    )
                    had_timeout = True
                    continue
                artifact_hash = self._file_hash(output_file)
                artifact_relpath = self._relative_artifact_path(output_file, project_root)
                self._write_tool_status(
                    "ander",
                    group_name,
                    fingerprint,
                    status="success",
                    timed_out=False,
                    result=result,
                    artifact_path=artifact_relpath,
                    artifact_hash=artifact_hash,
                )
                if not self._materialize_group(
                    "ander",
                    group_name,
                    fingerprint,
                    output_file,
                    artifact_hash,
                    artifact_relpath,
                ):
                    logger.warning(
                        "SVF group failed: event=recovery_failed tool=ander group=%s",
                        group_name,
                    )
                    had_timeout = True
                    continue
                logger.info("SVF resume: event=tool_rerun tool=ander group=%s", group_name)
        return had_timeout

    def _run_saber_groups(
        self,
        runner: Any,
        saber_paths: Dict[str, Path],
        project_root: Path,
    ) -> bool:
        if not saber_paths:
            return False
        # Resume checks touch the DB and cached artifacts only; keep them serial
        # so cached groups never occupy a worker slot.
        pending_paths: Dict[str, Path] = {}
        fingerprints: Dict[str, str] = {}
        for group_name, bc_path in sorted(saber_paths.items()):
            fingerprint = self._tool_artifact_fingerprint("saber", group_name, bc_path)
            fingerprints[group_name] = fingerprint
            status = self._load_tool_status("saber", group_name)
            artifact = self._validated_replay_artifact(
                "saber", group_name, fingerprint, status, project_root
            )
            if artifact and self._materialization_marker_valid(
                "saber", group_name, fingerprint, artifact[1]
            ):
                logger.info(
                    "SVF resume: event=cache_skip tool=saber group=%s",
                    group_name,
                )
                continue
            if artifact:
                artifact_path, artifact_hash, artifact_relpath = artifact
                if self._materialize_group(
                    "saber",
                    group_name,
                    fingerprint,
                    artifact_path,
                    artifact_hash,
                    artifact_relpath,
                ):
                    logger.info(
                        "SVF resume: event=artifact_reimport tool=saber group=%s",
                        group_name,
                    )
                    continue
                logger.warning(
                    "SVF resume: event=recovery_failed tool=saber group=%s; rerunning tool",
                    group_name,
                )
            pending_paths[group_name] = bc_path
        if not pending_paths:
            return False

        max_workers = self._saber_worker_count(len(pending_paths))
        logger.info(
            "Running %d Saber group(s) with %d worker(s)",
            len(pending_paths),
            max_workers,
        )
        had_failure = False
        if max_workers <= 1:
            for group_name, bc_path in pending_paths.items():
                if not self._run_one_saber_group(
                    runner,
                    group_name,
                    bc_path,
                    project_root,
                    fingerprints[group_name],
                ):
                    had_failure = True
            return had_failure
        with ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="zscope-saber"
        ) as executor:
            futures = {
                executor.submit(
                    self._run_one_saber_group,
                    runner,
                    group_name,
                    bc_path,
                    project_root,
                    fingerprints[group_name],
                ): group_name
                for group_name, bc_path in pending_paths.items()
            }
            for future in as_completed(futures):
                group_name = futures[future]
                try:
                    if not future.result():
                        had_failure = True
                except Exception as exc:
                    logger.warning("Saber group failed: group=%s error=%s", group_name, exc)
                    self._write_tool_status(
                        "saber",
                        group_name,
                        fingerprints.get(group_name, ""),
                        status="failed",
                        timed_out=False,
                    )
                    had_failure = True
        return had_failure

    @staticmethod
    def _is_saber_group(group_name: str) -> bool:
        return str(group_name).startswith("saber:")

    @staticmethod
    def _safe_output_suffix(group_name: str) -> str:
        return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(group_name))

    @staticmethod
    def _tool_status_key(tool: str, group_name: str) -> str:
        return f"svf_tool_status:{tool}:{group_name}"

    @staticmethod
    def _materialization_marker_key(tool: str, group_name: str) -> str:
        return f"svf_db_import:{tool}:{group_name}"

    def _load_tool_status(self, tool: str, group_name: str) -> Dict[str, Any]:
        raw = self._db.get_metadata(self._tool_status_key(tool, group_name))
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _tool_status_success(self, tool: str, group_name: str, artifact_fingerprint: str) -> bool:
        data = self._load_tool_status(tool, group_name)
        return (
            data.get("status") == "success"
            and data.get("artifact_fingerprint") == artifact_fingerprint
        )

    def _write_tool_status(
        self,
        tool: str,
        group_name: str,
        artifact_fingerprint: str,
        *,
        status: str,
        timed_out: bool,
        result: Optional[SvfResult] = None,
        artifact_path: str = "",
        artifact_hash: str = "",
    ) -> None:
        payload = {
            "artifact_fingerprint": artifact_fingerprint,
            "status": status,
            "timed_out": timed_out,
            "updated_at": time.time(),
            "artifact_path": artifact_path,
            "artifact_hash": artifact_hash,
            "output_hash": artifact_hash,
        }
        self._db.set_metadata(
            self._tool_status_key(tool, group_name),
            json.dumps(payload, sort_keys=True),
        )

    def _validated_replay_artifact(
        self,
        tool: str,
        group_name: str,
        artifact_fingerprint: str,
        status: Dict[str, Any],
        project_root: Path,
    ) -> Optional[tuple[Path, str, str]]:
        if (
            status.get("status") != "success"
            or status.get("artifact_fingerprint") != artifact_fingerprint
        ):
            return None
        raw_path = str(status.get("artifact_path") or "")
        if raw_path:
            candidate = Path(raw_path)
            artifact_path = candidate if candidate.is_absolute() else project_root / candidate
        elif tool == "ander":
            artifact_path = self._ander_artifact_path(project_root, group_name)
        else:
            return None
        expected_hash = str(status.get("artifact_hash") or status.get("output_hash") or "")
        if not expected_hash or not artifact_path.is_file():
            return None
        actual_hash = self._file_hash(artifact_path)
        if actual_hash != expected_hash:
            logger.warning(
                "SVF resume: event=artifact_invalid tool=%s group=%s expected=%s actual=%s",
                tool,
                group_name,
                expected_hash[:12],
                actual_hash[:12],
            )
            return None
        return (
            artifact_path,
            actual_hash,
            self._relative_artifact_path(artifact_path, project_root),
        )

    def _materialization_marker_valid(
        self,
        tool: str,
        group_name: str,
        artifact_fingerprint: str,
        artifact_hash: str,
    ) -> bool:
        raw = self._db.get_metadata(self._materialization_marker_key(tool, group_name))
        if not raw:
            return False
        try:
            marker = json.loads(raw)
            row_count = int(marker.get("imported_row_count"))
            marker_generation = int(marker.get("db_generation", -1))
        except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
            return False
        return (
            marker.get("schema_version") == self.MATERIALIZATION_SCHEMA_VERSION
            and marker.get("artifact_fingerprint") == artifact_fingerprint
            and marker.get("artifact_hash") == artifact_hash
            and marker_generation == self._db.get_svf_db_generation()
            and row_count >= 0
        )

    def _materialize_group(
        self,
        tool: str,
        group_name: str,
        artifact_fingerprint: str,
        artifact_path: Path,
        artifact_hash: str,
        artifact_relpath: str,
    ) -> bool:
        try:
            bugs: List[Dict[str, Any]] = []
            if tool == "saber":
                data = json.loads(artifact_path.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or not isinstance(data.get("bugs"), list):
                    raise ValueError("invalid Saber replay artifact")
                if not all(isinstance(item, dict) for item in data["bugs"]):
                    raise ValueError("invalid Saber bug entry")
                bugs = list(data["bugs"])

            generation = self._db.get_svf_db_generation()
            with self._db.svf_materialization_transaction():
                self._db.purge_svf_data(group=group_name, commit=False)
                mapper = SvfOutputMapper(
                    self._db,
                    svf_group=group_name,
                )
                if tool == "ander":
                    row_count = mapper.import_callgraph(artifact_path, commit=False)
                else:
                    row_count = mapper.import_saber_bugs(bugs, commit=False)
                marker = {
                    "schema_version": self.MATERIALIZATION_SCHEMA_VERSION,
                    "artifact_fingerprint": artifact_fingerprint,
                    "artifact_path": artifact_relpath,
                    "artifact_hash": artifact_hash,
                    "imported_row_count": int(row_count),
                    "db_generation": generation,
                    "imported_at": time.time(),
                }
                self._db.set_metadata(
                    self._materialization_marker_key(tool, group_name),
                    json.dumps(marker, sort_keys=True),
                    commit=False,
                )
            return True
        except Exception as exc:
            logger.warning(
                "SVF materialization failed: event=recovery_failed tool=%s group=%s error=%s",
                tool,
                group_name,
                exc,
            )
            return False

    def _materialization_current(self, project_root: Path) -> bool:
        raw = self._db.get_metadata(self.MATERIALIZATION_STATE_KEY)
        if not raw:
            return False
        try:
            state = json.loads(raw)
            groups = state.get("groups")
        except (json.JSONDecodeError, TypeError, AttributeError):
            return False
        generation = self._db.get_svf_db_generation()
        try:
            state_generation = int(state.get("db_generation", -1))
        except (TypeError, ValueError):
            return False
        if (
            state.get("schema_version") != self.MATERIALIZATION_SCHEMA_VERSION
            or state_generation != generation
            or not isinstance(groups, list)
        ):
            return False
        for item in groups:
            if not isinstance(item, dict):
                return False
            tool = str(item.get("tool") or "")
            group_name = str(item.get("group") or "")
            raw_marker = self._db.get_metadata(self._materialization_marker_key(tool, group_name))
            try:
                marker = json.loads(raw_marker)
            except (json.JSONDecodeError, TypeError):
                return False
            try:
                marker_generation = int(marker.get("db_generation", -1))
            except (TypeError, ValueError, AttributeError):
                return False
            if (
                marker.get("schema_version") != self.MATERIALIZATION_SCHEMA_VERSION
                or marker_generation != generation
            ):
                return False
            try:
                row_count = int(marker.get("imported_row_count"))
            except (TypeError, ValueError, AttributeError):
                return False
            artifact_fingerprint = str(marker.get("artifact_fingerprint") or "")
            artifact_hash = str(marker.get("artifact_hash") or "")
            artifact_relpath = str(marker.get("artifact_path") or "")
            status = self._load_tool_status(tool, group_name)
            if (
                row_count < 0
                or not artifact_fingerprint
                or not artifact_hash
                or not artifact_relpath
                or status.get("status") != "success"
                or status.get("artifact_fingerprint") != artifact_fingerprint
                or str(status.get("artifact_hash") or status.get("output_hash") or "")
                != artifact_hash
            ):
                return False
            artifact_path = Path(artifact_relpath)
            if not artifact_path.is_absolute():
                artifact_path = project_root / artifact_path
            if not artifact_path.is_file() or self._file_hash(artifact_path) != artifact_hash:
                return False
        return True

    def _mark_materialization_complete(self, bc_paths: Dict[str, Path]) -> None:
        generation = self._db.get_svf_db_generation()
        groups = [
            {
                "tool": "saber" if self._is_saber_group(group_name) else "ander",
                "group": group_name,
            }
            for group_name in sorted(bc_paths)
        ]
        for item in groups:
            raw = self._db.get_metadata(
                self._materialization_marker_key(item["tool"], item["group"])
            )
            if not raw:
                raise RuntimeError(
                    f"missing SVF materialization marker for {item['tool']}:{item['group']}"
                )
            marker = json.loads(raw)
            if int(marker.get("db_generation", -1)) != generation:
                raise RuntimeError(
                    f"stale SVF materialization marker for {item['tool']}:{item['group']}"
                )
        payload = {
            "schema_version": self.MATERIALIZATION_SCHEMA_VERSION,
            "db_generation": generation,
            "groups": groups,
            "updated_at": time.time(),
        }
        self._db.set_metadata(
            self.MATERIALIZATION_STATE_KEY,
            json.dumps(payload, sort_keys=True),
        )

    @staticmethod
    def _relative_artifact_path(artifact_path: Path, project_root: Path) -> str:
        return Path(
            os.path.relpath(Path(artifact_path).resolve(), Path(project_root).resolve())
        ).as_posix()

    def _ander_artifact_path(self, project_root: Path, group_name: str) -> Path:
        group_suffix = f"_{group_name}" if group_name != "default" else ""
        return project_root / f".zscope_svf{group_suffix}" / "callgraph_final.dot"

    def _write_saber_artifact(
        self,
        output_dir: Path,
        bugs: Sequence[Dict[str, Any]],
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        normalized = sorted(
            (dict(item) for item in bugs),
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
        payload = {
            "schema_version": self.MATERIALIZATION_SCHEMA_VERSION,
            "bugs": normalized,
        }
        artifact_path = output_dir / "saber_results.json"
        temporary_path = output_dir / (
            f".{artifact_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            temporary_path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(artifact_path)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
        return artifact_path

    def _tool_artifact_fingerprint(self, tool: str, group_name: str, bc_path: Path) -> str:
        payload = {
            "tool": tool,
            "group": group_name,
            "bc_path": str(Path(bc_path).resolve()),
            "bc_hash": self._file_hash(Path(bc_path)),
            "timeout": self._timeout,
            "heap_limit_mb": self._heap_limit,
            "svf_bin_dir": str(self._svf_bin_dir or ""),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            digest.update(b"__missing__")
        return digest.hexdigest()

    def _run_one_wpa_group(
        self,
        runner: Any,
        group_name: str,
        bc_path: Path,
        project_root: Path,
    ) -> SvfResult:
        logger.info("Running WPA analysis for group '%s' using %s", group_name, bc_path)
        group_suffix = f"_{group_name}" if group_name != "default" else ""
        output_dir = project_root / f".zscope_svf{group_suffix}"
        return cast(SvfResult, runner.run_ander(bc_path, output_dir))

    @staticmethod
    def _load_groups_config(project_root: Path, svf_groups_config: str) -> Dict[str, List[str]]:
        groups: Dict[str, List[str]] = {"default": []}
        if not svf_groups_config:
            return groups

        groups_path = Path(svf_groups_config)
        if not groups_path.is_absolute():
            groups_path = project_root / groups_path
        if not groups_path.exists():
            logger.warning("SVF groups config not found: %s", groups_path)
            return groups
        try:
            with open(groups_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {str(k): list(v or []) for k, v in data.items()}
        except (json.JSONDecodeError, OSError, TypeError) as exc:
            logger.error("Failed to parse SVF groups config %s: %s", groups_path, exc)
        return groups

    def _cache_config(self) -> Dict[str, Any]:
        return {
            "cache_schema_version": 3,
            "svf_bin_dir": str(self._svf_bin_dir or ""),
            "gclang_path": str(self._gclang),
            "get_bc_path": str(self._get_bc),
            "llvm_link_path": str(self._llvm_link),
            "heap_limit_mb": self._heap_limit,
            "timeout": self._timeout,
            "scope": self._scope_config.mode,
            "entry_depth": self._scope_config.entry_depth,
            "max_selected_tus": self._scope_config.max_selected_tus,
            "fallback": self._scope_config.fallback,
            "always_include": self._scope_config.always_include,
            "symbol_closure": self._scope_config.symbol_closure,
            "exclusive_pools": self._scope_config.exclusive_pools,
            "shared_pools": self._scope_config.shared_pools,
            "execution_lanes": "parallel_wpa_resumable_saber_groups",
            "parallel_workers": self._parallel_workers,
        }

    @staticmethod
    def _normalize_entry_functions(entries: Optional[Sequence[Any]]) -> List[str]:
        if not entries:
            return []
        normalized: List[str] = []
        seen = set()
        for entry in entries:
            name = entry.function_name if isinstance(entry, FunctionEntry) else entry
            if not name:
                continue
            name = str(name)
            if name in seen:
                continue
            seen.add(name)
            normalized.append(name)
        return normalized

    @staticmethod
    def _compute_aggregate_hash(
        compile_commands_path: Path,
        groups_config: Optional[Dict] = None,
        execution_config: Optional[Dict[str, Any]] = None,
        entry_functions: Optional[Sequence[str]] = None,
        *,
        sort_entry_functions: bool = True,
    ) -> str:
        try:
            with open(compile_commands_path, "r", encoding="utf-8") as f:
                commands = json.load(f)
        except (json.JSONDecodeError, OSError):
            return ""

        c_exts = {".c", ".cc", ".cpp", ".cxx"}
        source_files = []
        for cmd in commands:
            src = cmd.get("file", "")
            if Path(src).suffix.lower() in c_exts:
                src_path = Path(src)
                if not src_path.is_absolute():
                    src_path = Path(cmd.get("directory", ".")) / src_path
                source_files.append(src_path.resolve())
        source_files.sort()

        agg = hashlib.sha256()
        if groups_config:
            agg.update(json.dumps(groups_config, sort_keys=True).encode("utf-8"))
        if execution_config:
            agg.update(json.dumps(execution_config, sort_keys=True).encode("utf-8"))
        if entry_functions:
            entries = list(entry_functions)
            if sort_entry_functions:
                entries = sorted(entries)
            agg.update(json.dumps(entries, sort_keys=True).encode("utf-8"))

        for fp in source_files:
            agg.update(str(fp).encode("utf-8"))
            try:
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        agg.update(chunk)
            except OSError:
                agg.update(b"__missing__")
        return agg.hexdigest()[:32]

    @staticmethod
    def _compute_artifact_hash(
        bc_paths: Dict[str, Path],
        groups_config: Optional[Dict] = None,
        execution_config: Optional[Dict[str, Any]] = None,
        entry_functions: Optional[Sequence[str]] = None,
    ) -> str:
        agg = hashlib.sha256()
        if groups_config:
            agg.update(json.dumps(groups_config, sort_keys=True).encode("utf-8"))
        if execution_config:
            agg.update(json.dumps(execution_config, sort_keys=True).encode("utf-8"))
        if entry_functions:
            agg.update(json.dumps(sorted(entry_functions), sort_keys=True).encode("utf-8"))
        for group_name, path in sorted(bc_paths.items()):
            agg.update(str(group_name).encode("utf-8"))
            agg.update(str(Path(path).resolve()).encode("utf-8"))
            try:
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        agg.update(chunk)
            except OSError:
                agg.update(b"__missing__")
        return agg.hexdigest()[:32]

    def _saber_worker_count(self, group_count: int) -> int:
        """Bound parallel saber processes by configured workers and heap headroom.

        Each saber process may allocate up to the configured heap limit; the
        memory cap keeps concurrent tool processes within a bounded budget.
        """
        if group_count <= 0:
            return 0
        heap_workers = max(1, int(self._heap_limit) // _SABER_HEAP_PER_WORKER_MB)
        return max(1, min(int(self._parallel_workers or 1), group_count, heap_workers))

    def _run_one_saber_group(
        self,
        runner: Any,
        group_name: str,
        bc_path: Path,
        project_root: Path,
        fingerprint: str,
    ) -> bool:
        """Run and materialize one saber group. Returns False on any failure."""
        output_dir = project_root / f".zscope_svf_{self._safe_output_suffix(group_name)}"
        logger.info("Running Saber analysis for group %s using %s", group_name, bc_path)
        try:
            result = runner.run_saber(bc_path, output_dir)
        except Exception as exc:
            logger.warning("Saber group %s failed: %s", group_name, exc)
            self._write_tool_status(
                "saber",
                group_name,
                fingerprint,
                status="failed",
                timed_out=False,
            )
            return False
        if result.timed_out:
            self._write_tool_status(
                "saber",
                group_name,
                fingerprint,
                status="timed_out",
                timed_out=True,
                result=result,
            )
            return False
        if not result.success:
            self._write_tool_status(
                "saber",
                group_name,
                fingerprint,
                status="failed",
                timed_out=False,
                result=result,
            )
            return False
        try:
            artifact_path = self._write_saber_artifact(output_dir, result.bugs)
            artifact_hash = self._file_hash(artifact_path)
            artifact_relpath = self._relative_artifact_path(artifact_path, project_root)
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("Saber artifact persistence failed for group %s: %s", group_name, exc)
            self._write_tool_status(
                "saber",
                group_name,
                fingerprint,
                status="failed",
                timed_out=False,
                result=result,
            )
            return False
        self._write_tool_status(
            "saber",
            group_name,
            fingerprint,
            status="success",
            timed_out=False,
            result=result,
            artifact_path=artifact_relpath,
            artifact_hash=artifact_hash,
        )
        if not self._materialize_group(
            "saber",
            group_name,
            fingerprint,
            artifact_path,
            artifact_hash,
            artifact_relpath,
        ):
            logger.warning(
                "SVF group failed: event=recovery_failed tool=saber group=%s",
                group_name,
            )
            return False
        logger.info("SVF resume: event=tool_rerun tool=saber group=%s", group_name)
        return True

    @staticmethod
    def _lazy_bitcode_enabled() -> bool:
        """Lazy scope-first bitcode builds are opt-in via environment flag."""
        return os.environ.get("Z_SCOPE_SVF_LAZY_BITCODE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
