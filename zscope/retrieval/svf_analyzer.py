"""Run SVF tools and import their results into KnowledgeDB."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..config.function_entry import FunctionEntry
from .bitcode_scope import BitcodeScopeConfig
from .build_llvm import BitcodeBuilder
from .knowledge_db import KnowledgeDB
from .svf_parser import SvfOutputMapper
from .svf_runner import SvfResult, SvfRunner

logger = logging.getLogger(__name__)


class SvfAnalyzer:
    """Build bitcode, run SVF, and write indirect-call/Saber data."""

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
            if cache_fingerprint and old_hash in {
                cache_fingerprint,
                legacy_cache_fingerprint,
            }:
                if old_hash == legacy_cache_fingerprint and old_hash != cache_fingerprint:
                    self._db.set_svf_hash(cache_fingerprint)
                logger.info("SVF incremental: cache fingerprint unchanged; reusing cached data")
                return True
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
            bc_paths = self._build_bitcode(
                builder,
                groups=groups,
                scope_entries=scope_entries,
                project_root=project_root,
                explicit_groups_config=bool(svf_groups_config),
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
            if artifact_fingerprint and artifact_fingerprint == old_artifact_hash:
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
            if old_hash and bc_paths and set(bc_paths.keys()) == reused_linked_groups:
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
                logger.warning("SVF analysis timed out; cache fingerprint will not be updated")
                return False

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
    ) -> Dict[str, Path]:
        """Call BitcodeBuilder with scope kwargs when the implementation supports them."""
        try:
            params = inspect.signature(builder.build).parameters
        except (TypeError, ValueError):
            params = {}
        supports_scope_kwargs = (
            "scope_config" in params
            or any(param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values())
        )
        if not supports_scope_kwargs:
            return builder.build(groups=groups)
        return builder.build(
            groups=groups,
            scope_config=self._scope_config,
            entry_functions=scope_entries,
            knowledge_db=self._db,
            project_root=project_root,
            auto_entry_clusters=(
                self._scope_config.mode != "full"
                and bool(scope_entries)
            ),
            saber_groups=True,
        )

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
            if self._tool_status_success("ander", group_name, fingerprint):
                logger.info(
                    "SVF resume: skipping successful ander group '%s' (artifact unchanged)",
                    group_name,
                )
                continue
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
                if not result.success and not result.output_file:
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
                self._db.purge_svf_data(group=group_name)
                mapper = SvfOutputMapper(self._db, svf_group=group_name)
                if result.output_file:
                    mapper.import_callgraph(result.output_file)
                self._write_tool_status(
                    "ander",
                    group_name,
                    fingerprint,
                    status="success",
                    timed_out=False,
                    result=result,
                )
        return had_timeout

    def _run_saber_groups(
        self,
        runner: Any,
        saber_paths: Dict[str, Path],
        project_root: Path,
    ) -> bool:
        had_failure = False
        for group_name, bc_path in sorted(saber_paths.items()):
            fingerprint = self._tool_artifact_fingerprint("saber", group_name, bc_path)
            if self._tool_status_success("saber", group_name, fingerprint):
                logger.info(
                    "SVF resume: skipping successful saber group '%s' (artifact unchanged)",
                    group_name,
                )
                continue
            output_dir = project_root / f".zscope_svf_{self._safe_output_suffix(group_name)}"
            logger.info("Running Saber analysis for group '%s' using %s", group_name, bc_path)
            try:
                result = runner.run_saber(bc_path, output_dir)
            except Exception as exc:
                logger.warning("Saber group '%s' failed: %s", group_name, exc)
                self._write_tool_status(
                    "saber",
                    group_name,
                    fingerprint,
                    status="failed",
                    timed_out=False,
                )
                had_failure = True
                continue
            if result.timed_out:
                self._write_tool_status(
                    "saber",
                    group_name,
                    fingerprint,
                    status="timed_out",
                    timed_out=True,
                    result=result,
                )
                had_failure = True
                continue
            if not result.success:
                self._write_tool_status(
                    "saber",
                    group_name,
                    fingerprint,
                    status="failed",
                    timed_out=False,
                    result=result,
                )
                had_failure = True
                continue
            self._db.purge_svf_data(group=group_name)
            mapper = SvfOutputMapper(self._db, svf_group=group_name)
            if result.bugs:
                mapper.import_saber_bugs(result.bugs)
            self._write_tool_status(
                "saber",
                group_name,
                fingerprint,
                status="success",
                timed_out=False,
                result=result,
            )
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

    def _tool_status_success(self, tool: str, group_name: str, artifact_fingerprint: str) -> bool:
        raw = self._db.get_metadata(self._tool_status_key(tool, group_name))
        if not raw:
            return False
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return False
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
    ) -> None:
        output_hash = ""
        output_file = getattr(result, "output_file", None) if result else None
        if output_file:
            output_hash = self._file_hash(Path(output_file))
        elif result and result.bugs:
            output_hash = hashlib.sha256(
                json.dumps(result.bugs, sort_keys=True).encode("utf-8")
            ).hexdigest()
        payload = {
            "artifact_fingerprint": artifact_fingerprint,
            "status": status,
            "timed_out": timed_out,
            "updated_at": time.time(),
            "output_hash": output_hash,
        }
        self._db.set_metadata(
            self._tool_status_key(tool, group_name),
            json.dumps(payload, sort_keys=True),
        )

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
        return runner.run_ander(bc_path, output_dir)

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
