"""Run SVF tools and import their results into KnowledgeDB."""

from __future__ import annotations

import hashlib
import json
import logging
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
        max_selected_tus: int = 300,
        fallback: str = "full",
        always_include: Optional[List[str]] = None,
        symbol_closure: bool = True,
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
        )
        self._results: Dict[str, SvfResult] = {}

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
            old_hash = self._db.get_svf_hash()
            if cache_fingerprint and cache_fingerprint == old_hash:
                logger.info("SVF incremental: cache fingerprint unchanged; reusing cached data")
                return True

            builder = BitcodeBuilder(
                source_root=source_path,
                compile_commands_path=compile_commands_path,
                gclang_path=self._gclang,
                get_bc_path=self._get_bc,
                llvm_link_path=self._llvm_link,
                timeout=self._timeout,
            )
            if normalized_entries and self._scope_config.mode != "full":
                bc_paths = builder.build(
                    groups=groups,
                    scope_config=self._scope_config,
                    entry_functions=scope_entries,
                    knowledge_db=self._db,
                    project_root=project_root,
                )
            else:
                bc_paths = builder.build(groups=groups)

            if not bc_paths:
                logger.warning("Bitcode build failed or no bitcode generated; SVF skipped")
                return True

            runner = SvfRunner(
                svf_bin_dir=self._svf_bin_dir,
                heap_limit_mb=self._heap_limit,
                timeout=self._timeout,
            )

            had_timeout = False
            for group_name, bc_path in bc_paths.items():
                logger.info("Running SVF analysis for group '%s' using %s", group_name, bc_path)
                group_suffix = f"_{group_name}" if group_name != "default" else ""
                output_dir = project_root / f".zscope_svf{group_suffix}"

                self._results = runner.run_all(bc_path, output_dir)
                if any(result.timed_out for result in self._results.values()):
                    had_timeout = True

                self._db.purge_svf_data(group=group_name)
                mapper = SvfOutputMapper(self._db, svf_group=group_name)
                ander = self._results.get("ander")
                if ander and ander.output_file:
                    mapper.import_callgraph(ander.output_file)
                saber = self._results.get("saber")
                if saber and saber.bugs:
                    mapper.import_saber_bugs(saber.bugs)

            if had_timeout:
                logger.warning("SVF analysis timed out; cache fingerprint will not be updated")
                return False

            if cache_fingerprint:
                self._db.set_svf_hash(cache_fingerprint)
            return True
        except Exception as exc:
            logger.error("SVF analysis failed: %s", exc)
            return False

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
            agg.update(json.dumps(list(entry_functions), sort_keys=True).encode("utf-8"))

        for fp in source_files:
            agg.update(str(fp).encode("utf-8"))
            try:
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        agg.update(chunk)
            except OSError:
                agg.update(b"__missing__")
        return agg.hexdigest()[:32]
