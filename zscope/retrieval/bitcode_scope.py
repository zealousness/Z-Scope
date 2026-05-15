"""Entry-guided bitcode selection for SVF runs."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)


@dataclass
class BitcodeScopeConfig:
    """Controls how aggressively SVF narrows linked bitcode."""

    mode: str = "auto"
    entry_depth: int = 4
    max_selected_tus: int = 300
    fallback: str = "full"
    always_include: List[str] = field(default_factory=list)
    symbol_closure: bool = True


@dataclass
class BitcodeSymbols:
    defined: Set[str] = field(default_factory=set)
    undefined: Set[str] = field(default_factory=set)


@dataclass
class BitcodeScopePlan:
    group_name: str
    mode: str
    entries: List[str]
    selected_sources: List[str]
    selected_bcs: List[str]
    reachable_functions: List[str] = field(default_factory=list)
    unresolved_entries: List[str] = field(default_factory=list)
    symbol_closure_added: List[str] = field(default_factory=list)
    fallback_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_name": self.group_name,
            "mode": self.mode,
            "entries": self.entries,
            "selected_sources": self.selected_sources,
            "selected_bcs": self.selected_bcs,
            "reachable_functions": self.reachable_functions,
            "unresolved_entries": self.unresolved_entries,
            "symbol_closure_added": self.symbol_closure_added,
            "fallback_reason": self.fallback_reason,
        }


class LlvmNmSymbolReader:
    """Reads defined and undefined symbols from LLVM bitcode files."""

    def __init__(self, llvm_nm_path: str = "") -> None:
        self.llvm_nm_path = llvm_nm_path or self._find_llvm_nm()
        self._available: Optional[bool] = None

    def read_symbols(self, bc_path: Path) -> BitcodeSymbols:
        if not self._is_available():
            return BitcodeSymbols()
        defined = self._run_nm(bc_path, ["--defined-only"])
        undefined = self._run_nm(bc_path, ["--undefined-only"])
        return BitcodeSymbols(defined=defined, undefined=undefined)

    def _is_available(self) -> bool:
        if self._available is None:
            self._available = bool(self.llvm_nm_path and shutil.which(self.llvm_nm_path))
            if not self._available:
                logger.info("llvm-nm not found; SVF bitcode symbol closure is disabled")
        return self._available

    def _run_nm(self, bc_path: Path, flags: Sequence[str]) -> Set[str]:
        try:
            proc = subprocess.run(
                [self.llvm_nm_path, *flags, str(bc_path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("llvm-nm failed for %s: %s", bc_path, exc)
            return set()
        return self._parse_symbols(proc.stdout)

    @staticmethod
    def _parse_symbols(text: str) -> Set[str]:
        symbols: Set[str] = set()
        for line in text.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            symbol = parts[-1]
            if symbol and symbol not in {"U", "T", "t", "D", "d", "B", "b"}:
                symbols.add(symbol)
        return symbols

    @staticmethod
    def _find_llvm_nm() -> str:
        for candidate in ("llvm-nm", "llvm-nm.exe"):
            if shutil.which(candidate):
                return candidate
        return "llvm-nm"


class EntryBitcodeSelector:
    """Selects a conservative subset of bitcode for entry-scoped SVF."""

    def __init__(
        self,
        *,
        db: KnowledgeDB,
        source_root: Path,
        project_root: Path,
        config: BitcodeScopeConfig,
        symbol_reader: Optional[Any] = None,
    ) -> None:
        self.db = db
        self.source_root = Path(source_root).resolve()
        self.project_root = Path(project_root).resolve()
        self.config = config
        self.symbol_reader = symbol_reader or LlvmNmSymbolReader()

    def select(
        self,
        *,
        group_name: str,
        candidate_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
        entries: Sequence[Any],
    ) -> tuple[List[Path], BitcodeScopePlan]:
        entry_records = self._entry_records(entries)
        entry_names = [record["name"] for record in entry_records]
        all_bcs = [Path(p).resolve() for p in candidate_bcs]
        if self.config.mode == "full" or not entry_names:
            return all_bcs, self._full_plan(group_name, entry_names, all_bcs, bc_to_src)

        source_to_bcs = self._source_to_bcs(all_bcs, bc_to_src)
        reachable, selected_sources, unresolved = self._reachable_sources(entry_records)
        selected_sources.update(self._always_include_sources(source_to_bcs.keys()))

        selected_bcs: Set[Path] = set()
        for src in selected_sources:
            selected_bcs.update(source_to_bcs.get(src, []))

        fallback_reason = ""
        if not selected_bcs:
            fallback_reason = "no_bitcode_selected"
            selected_bcs = self._fallback_bcs(all_bcs)

        if (
            self.config.max_selected_tus > 0
            and len(selected_bcs) > self.config.max_selected_tus
        ):
            fallback_reason = (
                f"selected_tu_count_exceeded:{len(selected_bcs)}>"
                f"{self.config.max_selected_tus}"
            )
            selected_bcs = self._fallback_bcs(all_bcs)

        symbol_added: Set[Path] = set()
        if self.config.symbol_closure and selected_bcs and len(selected_bcs) < len(all_bcs):
            symbol_added = self._expand_symbol_closure(selected_bcs, all_bcs)
            selected_bcs.update(symbol_added)

        ordered_bcs = self._ordered_subset(all_bcs, selected_bcs)
        plan = BitcodeScopePlan(
            group_name=group_name,
            mode=self.config.mode,
            entries=entry_names,
            selected_sources=self._format_paths(selected_sources),
            selected_bcs=self._format_paths(ordered_bcs),
            reachable_functions=sorted(reachable),
            unresolved_entries=sorted(unresolved),
            symbol_closure_added=self._format_paths(symbol_added),
            fallback_reason=fallback_reason,
        )
        return ordered_bcs, plan

    def write_plan(self, plan: BitcodeScopePlan, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        plan_path = output_dir / f"bitcode_scope_{plan.group_name}.json"
        plan_path.write_text(
            json.dumps(plan.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _reachable_sources(
        self,
        entry_records: Sequence[Dict[str, str]],
    ) -> tuple[Set[str], Set[Path], Set[str]]:
        reachable: Set[str] = set()
        selected_sources: Set[Path] = set()
        unresolved: Set[str] = set()
        queue: List[tuple[str, int]] = [(record["name"], 0) for record in entry_records]
        entry_file_hints = {
            record["name"]: record.get("file_path", "")
            for record in entry_records
            if record.get("file_path")
        }

        while queue:
            func_name, depth = queue.pop(0)
            if func_name in reachable:
                continue
            hinted_file = self._resolve_source_path(entry_file_hints.get(func_name, ""))
            if hinted_file:
                selected_sources.add(hinted_file)
            func = self.db.get_function(func_name)
            if not func:
                if depth == 0:
                    unresolved.add(func_name)
                continue
            reachable.add(func_name)
            file_path = self._resolve_source_path(str(func.get("file_path") or func.get("file") or ""))
            if file_path:
                selected_sources.add(file_path)

            if depth >= self.config.entry_depth:
                continue
            for callee in self.db.get_callees(func_name, limit=10000):
                callee_name = str(callee.get("name") or "")
                if not callee_name or callee_name in reachable:
                    continue
                callee_file = self._resolve_source_path(str(callee.get("filename") or ""))
                if callee_file:
                    selected_sources.add(callee_file)
                queue.append((callee_name, depth + 1))

        return reachable, selected_sources, unresolved

    def _always_include_sources(self, sources: Iterable[Path]) -> Set[Path]:
        if not self.config.always_include:
            return set()
        selected: Set[Path] = set()
        for src in sources:
            src_text = src.as_posix()
            for pattern in self.config.always_include:
                if self._matches_include(src, src_text, pattern):
                    selected.add(src)
                    break
        return selected

    def _matches_include(self, src: Path, src_text: str, pattern: str) -> bool:
        raw = Path(pattern)
        candidates = []
        if raw.is_absolute():
            candidates.append(raw)
        else:
            candidates.append(self.source_root / raw)
            candidates.append(self.project_root / raw)
        for candidate in candidates:
            try:
                if src == candidate.resolve() or src.is_relative_to(candidate.resolve()):
                    return True
            except (OSError, ValueError):
                pass
        return pattern.replace("\\", "/") in src_text

    def _expand_symbol_closure(self, selected_bcs: Set[Path], all_bcs: Sequence[Path]) -> Set[Path]:
        symbol_cache: Dict[Path, BitcodeSymbols] = {}
        providers: Dict[str, Path] = {}
        for bc in all_bcs:
            symbols = self._read_symbols_cached(symbol_cache, bc)
            for symbol in symbols.defined:
                providers.setdefault(symbol, bc)

        added: Set[Path] = set()
        changed = True
        while changed:
            changed = False
            unresolved_symbols: Set[str] = set()
            for bc in list(selected_bcs):
                symbols = self._read_symbols_cached(symbol_cache, bc)
                unresolved_symbols.update(symbols.undefined)

            defined_in_selection: Set[str] = set()
            for bc in selected_bcs:
                defined_in_selection.update(self._read_symbols_cached(symbol_cache, bc).defined)

            for symbol in sorted(unresolved_symbols - defined_in_selection):
                provider = providers.get(symbol)
                if provider and provider not in selected_bcs:
                    selected_bcs.add(provider)
                    added.add(provider)
                    changed = True

        return added

    def _read_symbols_cached(
        self,
        cache: Dict[Path, BitcodeSymbols],
        bc_path: Path,
    ) -> BitcodeSymbols:
        if bc_path not in cache:
            cache[bc_path] = self.symbol_reader.read_symbols(bc_path)
        return cache[bc_path]

    def _fallback_bcs(self, all_bcs: Sequence[Path]) -> Set[Path]:
        if self.config.fallback == "skip":
            return set()
        return set(all_bcs)

    def _full_plan(
        self,
        group_name: str,
        entry_names: Sequence[str],
        all_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
    ) -> BitcodeScopePlan:
        normalized_map = {Path(bc).resolve(): src for bc, src in bc_to_src.items()}
        sources = [normalized_map.get(Path(bc).resolve(), Path("")) for bc in all_bcs]
        return BitcodeScopePlan(
            group_name=group_name,
            mode="full",
            entries=list(entry_names),
            selected_sources=self._format_paths(p for p in sources if str(p)),
            selected_bcs=self._format_paths(all_bcs),
        )

    def _source_to_bcs(
        self,
        all_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
    ) -> Dict[Path, List[Path]]:
        normalized_map = {Path(bc).resolve(): src for bc, src in bc_to_src.items()}
        result: Dict[Path, List[Path]] = {}
        for bc in all_bcs:
            src = self._resolve_source_path(str(normalized_map.get(Path(bc).resolve(), "")))
            if src:
                result.setdefault(src, []).append(Path(bc).resolve())
        return result

    def _resolve_source_path(self, file_path: str) -> Optional[Path]:
        if not file_path:
            return None
        raw = Path(file_path)
        candidates = [raw] if raw.is_absolute() else [self.source_root / raw, self.project_root / raw]
        for candidate in candidates:
            try:
                return candidate.resolve()
            except OSError:
                continue
        return candidates[0].absolute()

    @staticmethod
    def _entry_records(entries: Sequence[Any]) -> List[Dict[str, str]]:
        records: List[Dict[str, str]] = []
        seen: Set[str] = set()
        for entry in entries:
            name = getattr(entry, "function_name", entry)
            if not name:
                continue
            name = str(name)
            if name in seen:
                continue
            seen.add(name)
            records.append(
                {
                    "name": name,
                    "file_path": str(getattr(entry, "file_path", "") or ""),
                }
            )
        return records

    @staticmethod
    def _ordered_subset(all_bcs: Sequence[Path], selected_bcs: Set[Path]) -> List[Path]:
        selected = {Path(p).resolve() for p in selected_bcs}
        return [Path(bc).resolve() for bc in all_bcs if Path(bc).resolve() in selected]

    def _format_paths(self, paths: Iterable[Path]) -> List[str]:
        formatted: List[str] = []
        for path in sorted({Path(p).resolve() for p in paths}, key=lambda p: p.as_posix()):
            try:
                formatted.append(path.relative_to(self.project_root).as_posix())
            except ValueError:
                formatted.append(path.as_posix())
        return formatted
