"""Unified backend: Clang extraction plus optional SVF enrichment."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from .backend_base import CodeBackend
from .clang_backend import ClangBackend
from .knowledge_db import KnowledgeDB
from .svf_analyzer import SvfAnalyzer

logger = logging.getLogger(__name__)


class UnifiedBackend(CodeBackend):
    """Facade that shares one KnowledgeDB between Clang and SVF."""

    def __init__(
        self,
        clangd_path: str = "clangd",
        db_path: str = ".zscope_knowledge/code_knowledge.db",
        batch_size: int = 50,
        max_threads: int = 8,
        svf_bin_dir: str = "",
        gclang_path: str = "gclang",
        get_bc_path: str = "get-bc",
        llvm_link_path: str = "llvm-link",
        svf_heap_limit_mb: int = 32768,
        svf_timeout: int = 1800,
        svf_groups_config: str = "",
        svf_scope: str = "auto",
        svf_entry_depth: int = 4,
        svf_max_selected_tus: int = 300,
        svf_fallback: str = "full",
        svf_always_include: Optional[List[str]] = None,
        svf_symbol_closure: bool = True,
    ):
        self._clang = ClangBackend(
            clangd_path=clangd_path,
            db_path=db_path,
            batch_size=batch_size,
            max_threads=max_threads,
        )
        self._svf_cfg: Dict[str, Any] = dict(
            svf_bin_dir=svf_bin_dir,
            gclang_path=gclang_path,
            get_bc_path=get_bc_path,
            llvm_link_path=llvm_link_path,
            heap_limit_mb=svf_heap_limit_mb,
            timeout=svf_timeout,
            scope=svf_scope,
            entry_depth=svf_entry_depth,
            max_selected_tus=svf_max_selected_tus,
            fallback=svf_fallback,
            always_include=list(svf_always_include or []),
            symbol_closure=svf_symbol_closure,
        )
        self._svf_groups_config = svf_groups_config
        self._svf: Optional[SvfAnalyzer] = None
        self._svf_available = False
        self._svf_ran = False
        self._source_path: Optional[Path] = None
        self._project_root: Optional[Path] = None
        self._compile_commands_path: Optional[str] = None
        self._status = "idle"

    @property
    def db(self) -> Optional[KnowledgeDB]:
        return self._clang._db

    def initialize(self, source_path: str, **kwargs) -> bool:
        self._status = "building"
        self._svf_available = False
        self._svf_ran = False
        wait = kwargs.get("wait", True)
        self._source_path = Path(source_path)
        self._project_root = Path(kwargs.get("project_root", source_path))
        self._compile_commands_path = kwargs.get("compile_commands_path")

        ok = self._clang.initialize(source_path, **kwargs)
        if not ok:
            self._status = "error"
            return False

        if not wait:
            self._status = "ready"
            return True

        if kwargs.get("defer_svf", False):
            logger.info("SVF analysis deferred until entry functions are available")
            self._status = "ready"
            return True

        self.run_svf(entry_functions=kwargs.get("svf_entry_functions"))
        self._status = "ready"
        return True

    def run_svf(self, entry_functions: Optional[List[Any]] = None) -> bool:
        if self._svf_ran:
            return self._svf_available
        if not self._clang._db:
            self._svf_ran = True
            self._svf_available = False
            return False

        missing = self._check_svf_tools()
        if missing:
            logger.warning("SVF tools unavailable; missing: %s", ", ".join(missing))
            self._svf_ran = True
            self._svf_available = False
            return False

        self._svf = SvfAnalyzer(db=self._clang._db, **self._svf_cfg)
        cc = Path(self._compile_commands_path) if self._compile_commands_path else None
        source_path = self._source_path or Path(".")
        project_root = self._project_root or source_path
        svf_ok = self._svf.run(
            Path(source_path),
            Path(project_root),
            cc,
            svf_groups_config=self._svf_groups_config,
            entry_functions=entry_functions,
        )
        self._svf_ran = True
        self._svf_available = bool(svf_ok)
        if svf_ok:
            logger.info("SVF analysis completed and wrote results to KnowledgeDB")
        else:
            logger.warning("SVF analysis failed; indirect-call and Saber data are unavailable")
        return self._svf_available

    def _check_svf_tools(self) -> List[str]:
        missing: List[str] = []
        gclang = str(self._svf_cfg.get("gclang_path", "gclang"))
        if not shutil.which(gclang):
            missing.append(f"gclang ({gclang})")
        llvm_link = str(self._svf_cfg.get("llvm_link_path", "llvm-link"))
        if not shutil.which(llvm_link):
            missing.append(f"llvm-link ({llvm_link})")

        svf_bin = str(self._svf_cfg.get("svf_bin_dir", ""))
        if svf_bin:
            wpa = Path(svf_bin) / "wpa"
            saber = Path(svf_bin) / "saber"
            if not wpa.exists():
                missing.append(f"wpa ({wpa})")
            if not saber.exists():
                missing.append(f"saber ({saber})")
        else:
            if not shutil.which("wpa"):
                missing.append("wpa")
            if not shutil.which("saber"):
                missing.append("saber")
        return missing

    def close(self) -> None:
        self._clang.close()
        self._svf = None
        self._status = "idle"

    def status(self) -> str:
        return self._status

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        return self._clang.build_function_index()

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        return self._clang.get_method(name)

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self._clang.get_method_callees(name, limit)

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        return self._clang.get_type_info(type_name)

    def get_header_declared_functions(self, header_files=None) -> List[Dict[str, Any]]:
        return self._clang.get_header_declared_functions(header_files)

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        return self._clang.find_function_pointers(func_name)

    def get_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        direct = cast(List[Dict[str, Any]], db.get_callers(func_name, limit=limit))
        indirect = cast(List[Dict[str, Any]], db.get_indirect_callers(func_name, limit=limit))
        seen = {d["name"] for d in direct}
        for ic in indirect:
            if ic["name"] not in seen:
                direct.append(
                    {"name": ic["name"], "filename": ic.get("call_file", ""), "lineNumber": 0}
                )
        return cast(List[Dict[str, Any]], direct[:limit])

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        direct = cast(List[Dict[str, Any]], db.get_callees(func_name, limit=limit))
        indirect = cast(List[Dict[str, Any]], db.get_indirect_callees(func_name, limit=limit))
        seen = {d["name"] for d in direct}
        for ic in indirect:
            if ic["name"] not in seen:
                direct.append({"name": ic["name"], "source": ic.get("source", "svf")})
        return cast(List[Dict[str, Any]], direct[:limit])

    def get_data_flow(
        self,
        source_func: str,
        source_param: str,
        sink_pattern: str,
    ) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        return cast(
            List[Dict[str, Any]],
            db.get_enriched_taint_bugs(bug_type=sink_pattern, func_name=source_func),
        )

    def get_indirect_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        return cast(List[Dict[str, Any]], db.get_indirect_callees(func_name, limit=limit))

    def get_taint_bugs(self, bug_type: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        return cast(List[Dict[str, Any]], db.get_enriched_taint_bugs(bug_type=bug_type, limit=limit))
