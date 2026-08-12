"""Entry-guided bitcode selection for SVF runs."""

from __future__ import annotations

import json
import heapq
import logging
import shutil
import subprocess
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from ..common.utils import matches_configured_path, normalize_path
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)

ENTRY_CLUSTER_STRATEGY_VERSION = "cost_agglomerative_v1"


def _bit_count(value: int) -> int:
    """Count set bits on Python 3.9 while using the native API when available."""

    native = getattr(value, "bit_count", None)
    if callable(native):
        return int(native())
    if value < 0:
        raise ValueError("bitset values must be non-negative")
    return bin(value).count("1")


@dataclass
class BitcodeScopeConfig:
    """Controls how aggressively SVF narrows linked bitcode."""

    mode: str = "auto"
    entry_depth: int = 4
    max_selected_tus: int = 200
    fallback: str = "full"
    always_include: List[str] = field(default_factory=list)
    symbol_closure: bool = True
    exclusive_pools: List[Dict[str, Any]] = field(default_factory=list)
    shared_pools: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BitcodeSymbols:
    defined: Set[str] = field(default_factory=set)
    undefined: Set[str] = field(default_factory=set)
    external_defined: Set[str] = field(default_factory=set)


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
    exclusive_pool: str = ""
    duplicate_symbols: List[Dict[str, Any]] = field(default_factory=list)
    link_variants: List[Dict[str, Any]] = field(default_factory=list)
    skipped_variants: List[Dict[str, Any]] = field(default_factory=list)

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
            "exclusive_pool": self.exclusive_pool,
            "duplicate_symbols": self.duplicate_symbols,
            "link_variants": self.link_variants,
            "skipped_variants": self.skipped_variants,
        }


@dataclass
class EntryBitcodeCluster:
    """A small WPA analysis group derived from one or more entry functions."""

    group_name: str
    entries: List[Any]
    selected_bcs: List[Path]
    plan: BitcodeScopePlan


def normalize_exclusive_pools(
    raw_pools: Optional[Sequence[Mapping[str, Any]]],
) -> List[Dict[str, Any]]:
    """Return valid exclusive pool records from config-like input."""
    pools: List[Dict[str, Any]] = []
    if not raw_pools:
        return pools
    for item in raw_pools:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip()
        raw_paths = item.get("paths") or item.get("path_patterns") or []
        if isinstance(raw_paths, str):
            paths = [raw_paths]
        elif isinstance(raw_paths, Sequence):
            paths = [str(path).strip() for path in raw_paths if str(path).strip()]
        else:
            paths = []
        if name and paths:
            pools.append({"name": name, "paths": paths})
    return pools


def normalize_shared_pools(
    raw_pools: Optional[Sequence[Mapping[str, Any]]],
) -> List[Dict[str, Any]]:
    """Return valid shared pool records, including optional conflicts."""
    pools: List[Dict[str, Any]] = []
    for item in normalize_exclusive_pools(raw_pools):
        raw_conflicts: Any = {}
        if isinstance(raw_pools, Sequence):
            for raw_item in raw_pools:
                if (
                    isinstance(raw_item, Mapping)
                    and str(raw_item.get("name") or "").strip() == item["name"]
                ):
                    raw_conflicts = raw_item.get("conflicts_with") or []
                    break
        if isinstance(raw_conflicts, str):
            conflicts = [raw_conflicts]
        elif isinstance(raw_conflicts, Sequence):
            conflicts = [str(value).strip() for value in raw_conflicts if str(value).strip()]
        else:
            conflicts = []
        pools.append({**item, "conflicts_with": conflicts})
    return pools


class ExclusivePoolClassifier:
    """Classify source/bitcode files into user-configured mutually exclusive pools."""

    def __init__(
        self,
        *,
        source_root: Path,
        project_root: Path,
        pools: Optional[Sequence[Mapping[str, Any]]],
        shared_pools: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> None:
        self.source_root = Path(source_root).resolve()
        self.project_root = Path(project_root).resolve()
        self.pools = normalize_exclusive_pools(pools)
        self.shared_pools = normalize_shared_pools(shared_pools)

    @property
    def enabled(self) -> bool:
        return bool(self.pools or self.shared_pools)

    def pool_for_bc(self, bc_path: Path, bc_to_src: Mapping[Path, Path]) -> str:
        normalized_map = {Path(bc).resolve(): src for bc, src in bc_to_src.items()}
        src = normalized_map.get(Path(bc_path).resolve())
        return self.pool_for_source(src) if src else ""

    def pool_for_source(self, source_path: Optional[Path]) -> str:
        if not source_path or not self.pools:
            return ""
        candidates = self._path_candidates(Path(source_path))
        for pool in self.pools:
            if any(matches_configured_path(candidate, pool["paths"]) for candidate in candidates):
                return str(pool["name"])
        return ""

    def shared_pools_for_bc(self, bc_path: Path, bc_to_src: Mapping[Path, Path]) -> List[str]:
        normalized_map = {Path(bc).resolve(): src for bc, src in bc_to_src.items()}
        src = normalized_map.get(Path(bc_path).resolve())
        return self.shared_pools_for_source(src) if src else []

    def shared_pools_for_source(self, source_path: Optional[Path]) -> List[str]:
        if not source_path or not self.shared_pools:
            return []
        candidates = self._path_candidates(Path(source_path))
        matches: List[str] = []
        for pool in self.shared_pools:
            if any(matches_configured_path(candidate, pool["paths"]) for candidate in candidates):
                matches.append(str(pool["name"]))
        return matches

    def shared_conflicts_for_bc(self, bc_path: Path, bc_to_src: Mapping[Path, Path]) -> Set[str]:
        normalized_map = {Path(bc).resolve(): src for bc, src in bc_to_src.items()}
        src = normalized_map.get(Path(bc_path).resolve())
        return self.shared_conflicts_for_source(src) if src else set()

    def shared_conflicts_for_source(self, source_path: Optional[Path]) -> Set[str]:
        if not source_path or not self.shared_pools:
            return set()
        candidates = self._path_candidates(Path(source_path))
        conflicts: Set[str] = set()
        for pool in self.shared_pools:
            if any(matches_configured_path(candidate, pool["paths"]) for candidate in candidates):
                conflicts.update(
                    str(value) for value in pool.get("conflicts_with", []) if str(value)
                )
        return conflicts

    def ordered_pool_names(self, pools: Iterable[str]) -> List[str]:
        wanted = {pool for pool in pools if pool}
        ordered = [str(pool["name"]) for pool in self.pools if str(pool["name"]) in wanted]
        ordered.extend(sorted(wanted - set(ordered)))
        return ordered

    def _path_candidates(self, source_path: Path) -> List[str]:
        candidates: List[str] = []
        seen: Set[str] = set()
        for value in (
            source_path.as_posix(),
            normalize_path(source_path, self.source_root).replace("\\", "/"),
            normalize_path(source_path, self.project_root).replace("\\", "/"),
            source_path.name,
        ):
            if value and value not in seen:
                candidates.append(value)
                seen.add(value)
        return candidates


class LlvmNmSymbolReader:
    """Reads defined and undefined symbols from LLVM bitcode files."""

    _STRONG_EXTERNAL_TYPES = {"T", "D", "B", "R", "S", "G"}

    def __init__(self, llvm_nm_path: str = "") -> None:
        self.llvm_nm_path = llvm_nm_path or self._find_llvm_nm()
        self._available: Optional[bool] = None

    def read_symbols(self, bc_path: Path) -> BitcodeSymbols:
        if not self._is_available():
            return BitcodeSymbols()
        defined = self._run_nm(bc_path, ["--defined-only"])
        undefined = self._run_nm(bc_path, ["--undefined-only"])
        external_defined = self._run_nm(
            bc_path,
            ["--defined-only", "--extern-only"],
            strong_external_only=True,
        )
        return BitcodeSymbols(
            defined=defined,
            undefined=undefined,
            external_defined=external_defined,
        )

    def _is_available(self) -> bool:
        if self._available is None:
            self._available = bool(self.llvm_nm_path and shutil.which(self.llvm_nm_path))
            if not self._available:
                logger.info("llvm-nm not found; SVF bitcode symbol closure is disabled")
        return self._available

    def _run_nm(
        self,
        bc_path: Path,
        flags: Sequence[str],
        *,
        strong_external_only: bool = False,
    ) -> Set[str]:
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
        return self._parse_symbols(proc.stdout, strong_external_only=strong_external_only)

    @staticmethod
    def _parse_symbols(text: str, *, strong_external_only: bool = False) -> Set[str]:
        symbols: Set[str] = set()
        for line in text.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            if strong_external_only:
                if len(parts) < 2 or parts[-2] not in LlvmNmSymbolReader._STRONG_EXTERNAL_TYPES:
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
        self.pool_classifier = ExclusivePoolClassifier(
            source_root=self.source_root,
            project_root=self.project_root,
            pools=self.config.exclusive_pools,
            shared_pools=self.config.shared_pools,
        )
        self._function_cache: Dict[tuple[str, str], Optional[Dict[str, Any]]] = {}
        self._functions_by_name_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._callees_cache: Dict[tuple[str, str], List[Dict[str, Any]]] = {}
        self._symbol_cache: Dict[Path, BitcodeSymbols] = {}
        self._seed_dependency_cache: Dict[
            tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]],
            Dict[str, Any],
        ] = {}

    def select(
        self,
        *,
        group_name: str,
        candidate_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
        entries: Sequence[Any],
    ) -> tuple[List[Path], BitcodeScopePlan]:
        return self._select(
            group_name=group_name,
            candidate_bcs=candidate_bcs,
            bc_to_src=bc_to_src,
            entries=entries,
            apply_symbol_closure=True,
        )

    def _select(
        self,
        *,
        group_name: str,
        candidate_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
        entries: Sequence[Any],
        apply_symbol_closure: bool,
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

        if self.config.max_selected_tus > 0 and len(selected_bcs) > self.config.max_selected_tus:
            fallback_reason = (
                f"selected_tu_count_exceeded:{len(selected_bcs)}>" f"{self.config.max_selected_tus}"
            )
            selected_bcs = self._fallback_bcs(all_bcs)

        symbol_added: Set[Path] = set()
        if (
            apply_symbol_closure
            and self.config.symbol_closure
            and selected_bcs
            and len(selected_bcs) < len(all_bcs)
        ):
            symbol_added = self._expand_symbol_closure(selected_bcs, all_bcs, bc_to_src)
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

    def cluster_entries(
        self,
        *,
        group_prefix: str,
        candidate_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
        entries: Sequence[Any],
        min_overlap: float = 0.6,
    ) -> List[EntryBitcodeCluster]:
        """Group entries with highly overlapping selected bitcode sets.

        This keeps WPA inputs small without running one SVF process per entry when
        related public APIs mostly touch the same translation units.
        """
        entry_records = self._entry_records(entries)
        all_bcs = [Path(p).resolve() for p in candidate_bcs]
        bc_to_src_norm = self._normalize_bc_to_src(bc_to_src)
        source_to_bcs = self._source_to_bcs(all_bcs, bc_to_src, normalized_bc_to_src=bc_to_src_norm)
        if not entry_records:
            selected, plan = self.select(
                group_name=group_prefix,
                candidate_bcs=all_bcs,
                bc_to_src=bc_to_src,
                entries=entries,
            )
            return [
                EntryBitcodeCluster(
                    group_name=group_prefix,
                    entries=list(entries),
                    selected_bcs=selected,
                    plan=plan,
                )
            ]

        entry_objects = self._entry_object_map(entries)
        seeds_by_bc: Dict[Path, Dict[str, Any]] = {}
        unresolved_entries: Set[str] = set()
        logger.info(
            "SVF entry clustering '%s': locating %d entry seed(s) from %d .bc",
            group_prefix,
            len(entry_records),
            len(all_bcs),
        )
        for idx, record in enumerate(entry_records, start=1):
            if idx == 1 or idx % 25 == 0 or idx == len(entry_records):
                logger.info(
                    "SVF entry clustering '%s': locating seed %d/%d (%s%s)",
                    group_prefix,
                    idx,
                    len(entry_records),
                    record["name"],
                    f" @ {record.get('file_path')}" if record.get("file_path") else "",
                )
            entry = entry_objects.get(
                (record["name"], record.get("file_path", "")),
                record["name"],
            )
            entry_bcs, entry_source = self._entry_initial_bcs(record, source_to_bcs)
            if not entry_bcs:
                unresolved_entries.add(record["name"])
                continue
            for entry_bc in entry_bcs:
                seed = seeds_by_bc.setdefault(
                    entry_bc,
                    {
                        "entries": [],
                        "entry_records": [],
                        "initial_bcs": {entry_bc},
                        "entry_sources": set(),
                    },
                )
                seed["entries"].append(entry)
                seed["entry_records"].append(record)
                if entry_source:
                    seed["entry_sources"].add(entry_source)
            if idx == 1 or idx % 25 == 0 or idx == len(entry_records):
                logger.info(
                    "SVF entry clustering '%s': located seed %d/%d -> %d .bc%s",
                    group_prefix,
                    idx,
                    len(entry_records),
                    len(entry_bcs),
                    f" ({entry_source.as_posix()})" if entry_source else "",
                )

        if not seeds_by_bc:
            selected, plan = self.select(
                group_name=group_prefix,
                candidate_bcs=all_bcs,
                bc_to_src=bc_to_src,
                entries=entries,
            )
            return (
                [
                    EntryBitcodeCluster(
                        group_name=group_prefix,
                        entries=list(entries),
                        selected_bcs=selected,
                        plan=plan,
                    )
                ]
                if selected
                else []
            )

        seeds: List[Dict[str, Any]] = []
        logger.info(
            "SVF entry clustering '%s': expanding dependencies for %d .bc seed(s)",
            group_prefix,
            len(seeds_by_bc),
        )
        pool_started_at = time.monotonic()
        pool_by_bc = self._pool_by_bc(
            all_bcs,
            bc_to_src,
            normalized_bc_to_src=bc_to_src_norm,
        )
        shared_conflicts_by_bc = self._shared_conflicts_by_bc(
            all_bcs,
            bc_to_src,
            normalized_bc_to_src=bc_to_src_norm,
        )
        pool_distribution = Counter(pool or "<none>" for pool in pool_by_bc.values())
        logger.info(
            "SVF entry clustering '%s': precomputed pool maps for %d .bc in %.3fs (pools=%s)",
            group_prefix,
            len(all_bcs),
            time.monotonic() - pool_started_at,
            ", ".join(f"{pool}:{count}" for pool, count in sorted(pool_distribution.items())),
        )
        allowed_scope_cache: Dict[tuple[str, ...], tuple[Set[Path], Set[Path]]] = {}
        for idx, seed in enumerate(seeds_by_bc.values(), start=1):
            logger.info(
                "SVF entry clustering '%s': expanding seed %d/%d (%d entr%s, %d initial .bc)",
                group_prefix,
                idx,
                len(seeds_by_bc),
                len(seed["entries"]),
                "y" if len(seed["entries"]) == 1 else "ies",
                len(seed["initial_bcs"]),
            )
            expanded = self._expand_seed_dependencies(
                initial_bcs=seed["initial_bcs"],
                entry_records=seed["entry_records"],
                all_bcs=all_bcs,
                normalized_bc_to_src=bc_to_src_norm,
                source_to_bcs=source_to_bcs,
                pool_by_bc=pool_by_bc,
                shared_conflicts_by_bc=shared_conflicts_by_bc,
                allowed_scope_cache=allowed_scope_cache,
            )
            seed.update(expanded)
            seed["unresolved"].update(unresolved_entries)
            seeds.append(seed)
            logger.info(
                "SVF entry clustering '%s': expanded seed %d/%d -> %d selected .bc, %d reachable function(s)",
                group_prefix,
                idx,
                len(seeds_by_bc),
                len(seed["selected"]),
                len(seed["reachable"]),
            )

        clusters = self._merge_seed_clusters_by_cost(
            seeds,
            group_prefix=group_prefix,
            all_bcs=all_bcs,
            min_overlap=min_overlap,
        )

        logger.info(
            "SVF entry clustering '%s': formed %d cluster(s) from %d seed(s)",
            group_prefix,
            len(clusters),
            len(seeds),
        )
        result: List[EntryBitcodeCluster] = []
        for idx, cluster in enumerate(clusters):
            group_name = f"{group_prefix}_{idx + 1}"
            logger.info(
                "SVF entry clustering '%s': finalizing cluster %d/%d (%d entr%s, %d selected .bc)",
                group_prefix,
                idx + 1,
                len(clusters),
                len(cluster["entries"]),
                "y" if len(cluster["entries"]) == 1 else "ies",
                len(cluster["selected"]),
            )
            selected, plan = self._finalize_entry_cluster(
                group_name=group_name,
                cluster=cluster,
                all_bcs=all_bcs,
                bc_to_src=bc_to_src,
            )
            logger.info(
                "SVF entry clustering '%s': finalized cluster %d/%d as '%s' with %d .bc%s",
                group_prefix,
                idx + 1,
                len(clusters),
                group_name,
                len(selected),
                f" (fallback={plan.fallback_reason})" if plan.fallback_reason else "",
            )
            if selected:
                result.append(
                    EntryBitcodeCluster(
                        group_name=group_name,
                        entries=list(cluster["entries"]),
                        selected_bcs=selected,
                        plan=plan,
                    )
                )
        return result

    def _entry_initial_bcs(
        self,
        record: Mapping[str, str],
        source_to_bcs: Mapping[Path, List[Path]],
    ) -> tuple[List[Path], Optional[Path]]:
        logger.debug(
            "SVF entry seed: resolving entry '%s'%s",
            record.get("name", ""),
            f" with hint {record.get('file_path')}" if record.get("file_path") else "",
        )
        func = self._entry_function(record, set(source_to_bcs))
        source = self._resolve_source_path(
            str(
                (func or {}).get("file_path")
                or (func or {}).get("file")
                or record.get("file_path")
                or ""
            )
        )
        if not source:
            logger.info(
                "SVF entry seed: unresolved entry '%s'%s",
                record.get("name", ""),
                f" with hint {record.get('file_path')}" if record.get("file_path") else "",
            )
            return [], None
        entry_bcs = [Path(bc).resolve() for bc in source_to_bcs.get(source, [])]
        if not entry_bcs:
            logger.info(
                "SVF entry seed: entry '%s' resolved to %s but no candidate .bc matched",
                record.get("name", ""),
                source.as_posix(),
            )
        return entry_bcs, source

    def _entry_function(
        self,
        record: Mapping[str, str],
        allowed_sources: Set[Path],
    ) -> Optional[Dict[str, Any]]:
        name = str(record.get("name") or "")
        file_hint = str(record.get("file_path") or "")
        logger.debug("SVF entry seed: querying function '%s' hint='%s'", name, file_hint)
        func = self._get_function(name, file_hint)
        if func:
            func_source = self._resolve_source_path(
                str(func.get("file_path") or func.get("file") or "")
            )
            if not allowed_sources or (func_source and func_source in allowed_sources):
                return func
            logger.info(
                "SVF entry seed: function '%s' first match %s is outside candidate .bc set; trying alternatives",
                name,
                func_source.as_posix() if func_source else "",
            )
        return self._best_callee_function(name, file_hint, allowed_sources=allowed_sources)

    def _expand_seed_dependencies(
        self,
        *,
        initial_bcs: Set[Path],
        entry_records: Sequence[Mapping[str, str]],
        all_bcs: Sequence[Path],
        normalized_bc_to_src: Mapping[Path, Path],
        source_to_bcs: Mapping[Path, List[Path]],
        pool_by_bc: Mapping[Path, str],
        shared_conflicts_by_bc: Mapping[Path, Set[str]],
        allowed_scope_cache: Dict[tuple[str, ...], tuple[Set[Path], Set[Path]]],
    ) -> Dict[str, Any]:
        entry_names = self._entry_names_from_records(entry_records)
        logger.info(
            "SVF seed dependency: start entries=%d initial_bcs=%d candidates=%d",
            len(entry_names),
            len(initial_bcs),
            len(all_bcs),
        )
        seed_pools = {
            pool_by_bc.get(Path(bc).resolve(), "")
            for bc in initial_bcs
            if pool_by_bc.get(Path(bc).resolve(), "")
        }
        logger.info(
            "SVF seed dependency: seed pools=%s",
            ",".join(sorted(seed_pools)) if seed_pools else "<none>",
        )
        allowed_cache_key = tuple(sorted(seed_pools))
        allowed_sources: Set[Path]
        if allowed_cache_key in allowed_scope_cache:
            cached_allowed_bcs, cached_allowed_sources = allowed_scope_cache[allowed_cache_key]
            allowed_bcs = set(cached_allowed_bcs)
            allowed_sources = set(cached_allowed_sources)
            logger.info(
                "SVF seed dependency: allowed scope cache hit for pools=%s",
                ",".join(allowed_cache_key) if allowed_cache_key else "<none>",
            )
        else:
            allowed_started_at = time.monotonic()
            allowed_bcs = {
                Path(bc).resolve()
                for bc in all_bcs
                if self._bc_compatible_with_seed_pools(
                    Path(bc).resolve(),
                    seed_pools,
                    pool_by_bc,
                    shared_conflicts_by_bc,
                )
            }
            allowed_sources = set()
            for bc in allowed_bcs:
                source = normalized_bc_to_src.get(Path(bc).resolve())
                if source is not None:
                    allowed_sources.add(source)
            allowed_scope_cache[allowed_cache_key] = (set(allowed_bcs), set(allowed_sources))
            logger.info(
                "SVF seed dependency: allowed scope cache miss for pools=%s; computed in %.3fs",
                ",".join(allowed_cache_key) if allowed_cache_key else "<none>",
                time.monotonic() - allowed_started_at,
            )
        cache_key = (
            tuple(sorted(Path(bc).resolve().as_posix() for bc in initial_bcs)),
            tuple(sorted(seed_pools)),
            tuple(sorted(Path(bc).resolve().as_posix() for bc in allowed_bcs)),
        )
        if cache_key in self._seed_dependency_cache:
            cached = self._seed_dependency_cache[cache_key]
            logger.info(
                "SVF seed dependency: cache hit -> %d selected .bc, %d reachable function(s)",
                len(cached["selected"]),
                len(cached["reachable"]),
            )
            return {
                "selected": set(cached["selected"]),
                "selected_sources": set(cached["selected_sources"]),
                "reachable": set(cached["reachable"]),
                "unresolved": set(cached["unresolved"]),
                "allowed_bcs": set(cached["allowed_bcs"]),
                "seed_pools": set(cached["seed_pools"]),
            }

        logger.info(
            "SVF seed dependency: allowed candidates=%d .bc / %d source file(s)",
            len(allowed_bcs),
            len(allowed_sources),
        )
        reachable_started_at = time.monotonic()
        reachable, selected_sources, unresolved = self._reachable_sources(
            entry_records,
            allowed_sources=allowed_sources,
        )
        logger.info(
            "SVF seed dependency: reachable source expansion completed in %.3fs",
            time.monotonic() - reachable_started_at,
        )
        selected_sources.update(
            src for src in self._always_include_sources(allowed_sources) if src in allowed_sources
        )
        selected_bcs = {
            Path(bc).resolve() for bc in initial_bcs if Path(bc).resolve() in allowed_bcs
        }
        for src in selected_sources:
            for bc in source_to_bcs.get(src, []):
                resolved_bc = Path(bc).resolve()
                if resolved_bc in allowed_bcs:
                    selected_bcs.add(resolved_bc)

        data: Dict[str, Set[Any]] = {
            "selected": selected_bcs,
            "selected_sources": selected_sources,
            "reachable": reachable,
            "unresolved": unresolved,
            "allowed_bcs": allowed_bcs,
            "seed_pools": seed_pools,
        }
        self._seed_dependency_cache[cache_key] = {key: set(value) for key, value in data.items()}
        logger.info(
            "SVF seed dependency: completed -> %d selected .bc, %d reachable function(s), %d unresolved entr%s",
            len(selected_bcs),
            len(reachable),
            len(unresolved),
            "y" if len(unresolved) == 1 else "ies",
        )
        return data

    def _merge_seed_clusters_by_cost(
        self,
        seeds: Sequence[Mapping[str, Any]],
        *,
        group_prefix: str,
        all_bcs: Sequence[Path],
        min_overlap: float,
    ) -> List[Dict[str, Any]]:
        if not seeds:
            return []

        bc_to_bit = {Path(bc).resolve(): idx for idx, bc in enumerate(all_bcs)}
        clusters: Dict[int, Dict[str, Any]] = {}
        bit_to_clusters: Dict[int, List[int]] = {}
        selected_sizes: List[int] = []

        for cluster_id, seed in enumerate(seeds):
            selected_bits = self._paths_to_bitset(seed.get("selected", set()), bc_to_bit)
            allowed_bits = self._paths_to_bitset(seed.get("allowed_bcs", set()), bc_to_bit)
            cluster = self._seed_to_merge_cluster(
                seed,
                cluster_id=cluster_id,
                order=cluster_id,
                selected_bits=selected_bits,
                allowed_bits=allowed_bits,
            )
            clusters[cluster_id] = cluster
            selected_sizes.append(cluster["selected_size"])
            for bit in self._iter_bit_indices(selected_bits):
                bit_to_clusters.setdefault(bit, []).append(cluster_id)

        cost_bias = self._entry_cluster_cost_bias(selected_sizes)
        initial_cost = self._entry_cluster_total_cost(clusters.values(), cost_bias)
        heap: List[tuple[float, int, int, int, int, int, int]] = []
        reject_stats: Counter[str] = Counter()
        scored_pairs = 0

        def push_candidate(left_id: int, right_id: int) -> None:
            nonlocal scored_pairs
            if left_id == right_id:
                return
            if left_id > right_id:
                left_id, right_id = right_id, left_id
            left = clusters.get(left_id)
            right = clusters.get(right_id)
            if not left or not right or not left["active"] or not right["active"]:
                return
            scored_pairs += 1
            score, reject_reason = self._score_seed_cluster_merge(
                left,
                right,
                cost_bias=cost_bias,
                min_overlap=min_overlap,
            )
            if score is None:
                reject_stats[reject_reason] += 1
                return
            gain, union_size = score
            heapq.heappush(
                heap,
                (
                    -gain,
                    union_size,
                    min(left["order"], right["order"]),
                    left_id,
                    right_id,
                    left["version"],
                    right["version"],
                ),
            )

        initial_pairs: Set[tuple[int, int]] = set()
        for cluster_ids in bit_to_clusters.values():
            unique_ids = sorted(set(cluster_ids))
            for left_idx, left_id in enumerate(unique_ids[:-1]):
                for right_id in unique_ids[left_idx + 1 :]:
                    initial_pairs.add((left_id, right_id))

        for left_id, right_id in sorted(initial_pairs):
            push_candidate(left_id, right_id)

        logger.info(
            "SVF entry clustering '%s': cost merge start seeds=%d candidate_pairs=%d "
            "scored_pairs=%d initial_cost=%.1f cost_bias=%.1f sizes=(%s)",
            group_prefix,
            len(seeds),
            len(initial_pairs),
            scored_pairs,
            initial_cost,
            cost_bias,
            self._entry_cluster_size_summary(selected_sizes),
        )

        active_ids = set(clusters)
        next_cluster_id = len(clusters)
        merge_count = 0
        stale_count = 0

        while heap:
            (
                negative_gain,
                _union_size,
                _order,
                left_id,
                right_id,
                left_version,
                right_version,
            ) = heapq.heappop(heap)
            left = clusters.get(left_id)
            right = clusters.get(right_id)
            if (
                not left
                or not right
                or not left["active"]
                or not right["active"]
                or left["version"] != left_version
                or right["version"] != right_version
            ):
                stale_count += 1
                continue

            merged = self._merge_seed_cluster_records(
                left,
                right,
                cluster_id=next_cluster_id,
            )
            neighbor_ids: Set[int] = set()
            for bit in self._iter_bit_indices(merged["selected_bits"]):
                for cluster_id in bit_to_clusters.get(bit, []):
                    if cluster_id in active_ids and cluster_id not in {left_id, right_id}:
                        neighbor_ids.add(cluster_id)

            left["active"] = False
            right["active"] = False
            left["version"] += 1
            right["version"] += 1
            active_ids.discard(left_id)
            active_ids.discard(right_id)
            clusters[next_cluster_id] = merged
            active_ids.add(next_cluster_id)
            for bit in self._iter_bit_indices(merged["selected_bits"]):
                bit_to_clusters.setdefault(bit, []).append(next_cluster_id)
            for neighbor_id in sorted(neighbor_ids):
                push_candidate(next_cluster_id, neighbor_id)

            merge_count += 1
            logger.debug(
                "SVF entry clustering '%s': merged cluster %d + %d -> %d "
                "(gain=%.1f, selected=%d)",
                group_prefix,
                left_id,
                right_id,
                next_cluster_id,
                -negative_gain,
                merged["selected_size"],
            )
            next_cluster_id += 1

        active_clusters = [
            clusters[cluster_id]
            for cluster_id in sorted(active_ids, key=lambda item: (clusters[item]["order"], item))
        ]
        final_sizes = [cluster["selected_size"] for cluster in active_clusters]
        final_cost = self._entry_cluster_total_cost(active_clusters, cost_bias)
        reject_text = (
            ", ".join(f"{reason}:{count}" for reason, count in sorted(reject_stats.items()))
            or "<none>"
        )
        logger.info(
            "SVF entry clustering '%s': cost merge completed %d -> %d cluster(s), "
            "merges=%d, scored_pairs=%d, stale_pairs=%d, estimated_cost %.1f -> %.1f",
            group_prefix,
            len(seeds),
            len(active_clusters),
            merge_count,
            scored_pairs,
            stale_count,
            initial_cost,
            final_cost,
        )
        logger.info(
            "SVF entry clustering '%s': final cluster selected .bc sizes=(%s), rejected=(%s)",
            group_prefix,
            self._entry_cluster_size_summary(final_sizes),
            reject_text,
        )
        return active_clusters

    def _seed_to_merge_cluster(
        self,
        seed: Mapping[str, Any],
        *,
        cluster_id: int,
        order: int,
        selected_bits: int,
        allowed_bits: int,
    ) -> Dict[str, Any]:
        entries = list(seed.get("entries", []))
        entry_records = list(seed.get("entry_records", []))
        entry_items = []
        for idx, entry in enumerate(entries):
            if idx < len(entry_records):
                record = entry_records[idx]
            else:
                record = {
                    "name": str(getattr(entry, "function_name", entry) or ""),
                    "file_path": str(getattr(entry, "file_path", "") or ""),
                }
            entry_items.append((order, idx, entry, record))
        return {
            "id": cluster_id,
            "version": 0,
            "active": True,
            "order": order,
            "entry_items": entry_items,
            "entries": entries,
            "entry_records": entry_records,
            "initial_bcs": set(seed.get("initial_bcs", set())),
            "entry_sources": set(seed.get("entry_sources", set())),
            "selected": set(seed.get("selected", set())),
            "selected_sources": set(seed.get("selected_sources", set())),
            "reachable": set(seed.get("reachable", set())),
            "unresolved": set(seed.get("unresolved", set())),
            "allowed_bcs": set(seed.get("allowed_bcs", set())),
            "seed_pools": set(seed.get("seed_pools", set())),
            "selected_bits": selected_bits,
            "allowed_bits": allowed_bits,
            "selected_size": _bit_count(selected_bits),
        }

    def _merge_seed_cluster_records(
        self,
        left: Mapping[str, Any],
        right: Mapping[str, Any],
        *,
        cluster_id: int,
    ) -> Dict[str, Any]:
        entry_items = sorted(
            list(left["entry_items"]) + list(right["entry_items"]),
            key=lambda item: (item[0], item[1]),
        )
        selected_bits = int(left["selected_bits"]) | int(right["selected_bits"])
        allowed_bits = int(left["allowed_bits"]) | int(right["allowed_bits"])
        return {
            "id": cluster_id,
            "version": 0,
            "active": True,
            "order": min(left["order"], right["order"]),
            "entry_items": entry_items,
            "entries": [item[2] for item in entry_items],
            "entry_records": [item[3] for item in entry_items],
            "initial_bcs": set(left["initial_bcs"]) | set(right["initial_bcs"]),
            "entry_sources": set(left["entry_sources"]) | set(right["entry_sources"]),
            "selected": set(left["selected"]) | set(right["selected"]),
            "selected_sources": set(left["selected_sources"]) | set(right["selected_sources"]),
            "reachable": set(left["reachable"]) | set(right["reachable"]),
            "unresolved": set(left["unresolved"]) | set(right["unresolved"]),
            "allowed_bcs": set(left["allowed_bcs"]) | set(right["allowed_bcs"]),
            "seed_pools": set(left["seed_pools"]) | set(right["seed_pools"]),
            "selected_bits": selected_bits,
            "allowed_bits": allowed_bits,
            "selected_size": _bit_count(selected_bits),
        }

    def _score_seed_cluster_merge(
        self,
        left: Mapping[str, Any],
        right: Mapping[str, Any],
        *,
        cost_bias: float,
        min_overlap: float,
    ) -> tuple[Optional[tuple[float, int]], str]:
        if not self._seed_pools_compatible(set(left["seed_pools"]), set(right["seed_pools"])):
            return None, "pool"
        left_bits = int(left["selected_bits"])
        right_bits = int(right["selected_bits"])
        intersection_size = _bit_count(left_bits & right_bits)
        if intersection_size <= 0:
            return None, "no_shared_bc"
        left_size = int(left["selected_size"])
        right_size = int(right["selected_size"])
        if left_size <= 0 or right_size <= 0:
            return None, "empty"
        union_size = _bit_count(left_bits | right_bits)
        max_tus = self.config.max_selected_tus
        if max_tus > 0 and union_size > max_tus:
            return None, "max_tus"
        jaccard = intersection_size / union_size if union_size else 0.0
        containment = intersection_size / min(left_size, right_size)
        if jaccard < min_overlap and containment < 0.95:
            return None, "overlap"
        gain = (
            self._entry_cluster_cost(left_size, cost_bias)
            + self._entry_cluster_cost(right_size, cost_bias)
            - self._entry_cluster_cost(union_size, cost_bias)
        )
        if gain <= 0:
            return None, "gain"
        return (gain, union_size), ""

    def _finalize_entry_cluster(
        self,
        *,
        group_name: str,
        cluster: Mapping[str, Any],
        all_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
    ) -> tuple[List[Path], BitcodeScopePlan]:
        allowed_bcs = {Path(bc).resolve() for bc in cluster["allowed_bcs"]}
        selected_bcs = {
            Path(bc).resolve() for bc in cluster["selected"] if Path(bc).resolve() in allowed_bcs
        }
        fallback_reason = ""
        if not selected_bcs:
            fallback_reason = "no_bitcode_selected"
            selected_bcs = self._fallback_bcs_for_allowed(allowed_bcs)
        if self.config.max_selected_tus > 0 and len(selected_bcs) > self.config.max_selected_tus:
            fallback_reason = (
                f"selected_tu_count_exceeded:{len(selected_bcs)}>" f"{self.config.max_selected_tus}"
            )
            selected_bcs = self._fallback_bcs_for_allowed(allowed_bcs)

        ordered_allowed_bcs = self._ordered_subset(all_bcs, allowed_bcs)
        symbol_added: Set[Path] = set()
        if (
            self.config.symbol_closure
            and selected_bcs
            and len(selected_bcs) < len(ordered_allowed_bcs)
        ):
            symbol_added = self._expand_symbol_closure(selected_bcs, ordered_allowed_bcs, bc_to_src)
            selected_bcs.update(symbol_added)
            if (
                self.config.max_selected_tus > 0
                and len(selected_bcs) > self.config.max_selected_tus
            ):
                fallback_reason = (
                    f"symbol_closure_tu_count_exceeded:{len(selected_bcs)}>"
                    f"{self.config.max_selected_tus}"
                )
                selected_bcs = self._fallback_bcs_for_allowed(allowed_bcs)
                symbol_added = set()

        ordered_bcs = self._ordered_subset(all_bcs, selected_bcs)
        entry_names = self._entry_names_from_records(cluster["entry_records"])
        plan = BitcodeScopePlan(
            group_name=group_name,
            mode=self.config.mode,
            entries=entry_names,
            selected_sources=self._format_paths(cluster["selected_sources"]),
            selected_bcs=self._format_paths(ordered_bcs),
            reachable_functions=sorted(cluster["reachable"]),
            unresolved_entries=sorted(cluster["unresolved"]),
            symbol_closure_added=self._format_paths(symbol_added),
            fallback_reason=fallback_reason,
            exclusive_pool=(
                next(iter(cluster["seed_pools"]), "") if len(cluster["seed_pools"]) == 1 else ""
            ),
        )
        return ordered_bcs, plan

    def _fallback_bcs_for_allowed(self, allowed_bcs: Set[Path]) -> Set[Path]:
        if self.config.fallback == "skip":
            return set()
        return {Path(bc).resolve() for bc in allowed_bcs}

    @staticmethod
    def _seed_pools_compatible(left: Set[str], right: Set[str]) -> bool:
        left_pools = {pool for pool in left if pool}
        right_pools = {pool for pool in right if pool}
        return not left_pools or not right_pools or left_pools == right_pools

    def _pool_by_bc(
        self,
        all_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
        *,
        normalized_bc_to_src: Optional[Mapping[Path, Path]] = None,
    ) -> Dict[Path, str]:
        normalized_map = (
            normalized_bc_to_src
            if normalized_bc_to_src is not None
            else self._normalize_bc_to_src(bc_to_src)
        )
        return {
            Path(bc).resolve(): self.pool_classifier.pool_for_source(
                normalized_map.get(Path(bc).resolve())
            )
            for bc in all_bcs
        }

    def _shared_conflicts_by_bc(
        self,
        all_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
        *,
        normalized_bc_to_src: Optional[Mapping[Path, Path]] = None,
    ) -> Dict[Path, Set[str]]:
        normalized_map = (
            normalized_bc_to_src
            if normalized_bc_to_src is not None
            else self._normalize_bc_to_src(bc_to_src)
        )
        return {
            Path(bc).resolve(): self.pool_classifier.shared_conflicts_for_source(
                normalized_map.get(Path(bc).resolve())
            )
            for bc in all_bcs
        }

    @staticmethod
    def _bc_compatible_with_seed_pools(
        bc: Path,
        seed_pools: Set[str],
        pool_by_bc: Mapping[Path, str],
        shared_conflicts_by_bc: Mapping[Path, Set[str]],
    ) -> bool:
        pool = pool_by_bc.get(Path(bc).resolve(), "")
        if pool:
            return pool in seed_pools
        conflicts = shared_conflicts_by_bc.get(Path(bc).resolve(), set())
        return not any(pool_name in conflicts for pool_name in seed_pools)

    @staticmethod
    def _entry_object_map(entries: Sequence[Any]) -> Dict[tuple[str, str], Any]:
        result: Dict[tuple[str, str], Any] = {}
        for entry in entries:
            name = getattr(entry, "function_name", entry)
            if not name:
                continue
            key = (str(name), str(getattr(entry, "file_path", "") or ""))
            result.setdefault(key, entry)
        return result

    @staticmethod
    def _entry_names_from_records(records: Sequence[Mapping[str, str]]) -> List[str]:
        names: List[str] = []
        seen: Set[str] = set()
        for record in records:
            name = str(record.get("name") or "")
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        return names

    def write_plan(self, plan: BitcodeScopePlan, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        plan_path = output_dir / f"bitcode_scope_{plan.group_name}.json"
        plan_path.write_text(
            json.dumps(plan.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _reachable_sources(
        self,
        entry_records: Sequence[Mapping[str, str]],
        *,
        allowed_sources: Optional[Set[Path]] = None,
    ) -> tuple[Set[str], Set[Path], Set[str]]:
        reachable: Set[str] = set()
        selected_sources: Set[Path] = set()
        unresolved: Set[str] = set()
        queue = deque(
            [(record["name"], 0, record.get("file_path", "")) for record in entry_records]
        )
        entry_file_hints = {
            record["name"]: record.get("file_path", "")
            for record in entry_records
            if record.get("file_path")
        }
        logger.info(
            "SVF reachable sources: start from %d entr%s, depth=%d, allowed_sources=%d",
            len(entry_records),
            "y" if len(entry_records) == 1 else "ies",
            self.config.entry_depth,
            len(allowed_sources) if allowed_sources is not None else -1,
        )
        processed = 0

        while queue:
            func_name, depth, file_hint = queue.popleft()
            reachable_key = f"{func_name}\0{file_hint}"
            if reachable_key in reachable:
                continue
            processed += 1
            if processed == 1 or processed % 500 == 0:
                logger.info(
                    "SVF reachable sources: processed %d function state(s), queue=%d, selected_sources=%d",
                    processed,
                    len(queue),
                    len(selected_sources),
                )
            hinted_file = self._resolve_source_path(
                file_hint or entry_file_hints.get(func_name, "")
            )
            if hinted_file:
                selected_sources.add(hinted_file)
            func = self._get_function(func_name, file_hint)
            func_source = self._resolve_source_path(
                str((func or {}).get("file_path") or (func or {}).get("file") or "")
            )
            if (
                func
                and allowed_sources is not None
                and (not func_source or func_source not in allowed_sources)
            ):
                func = self._best_callee_function(
                    func_name,
                    file_hint,
                    allowed_sources=allowed_sources,
                )
            if not func:
                if depth == 0:
                    unresolved.add(func_name)
                continue
            reachable.add(reachable_key)
            file_path = self._resolve_source_path(
                str(func.get("file_path") or func.get("file") or "")
            )
            if allowed_sources is not None and file_path and file_path not in allowed_sources:
                continue
            if file_path:
                selected_sources.add(file_path)

            if depth >= self.config.entry_depth:
                continue
            caller_file = str(func.get("file_path") or func.get("file") or file_hint or "")
            callees = self._get_callees(func_name, caller_file)
            for callee in callees:
                callee_name = str(callee.get("name") or "")
                callee_file_hint = str(callee.get("filename") or "")
                if not callee_file_hint:
                    callee_func = self._best_callee_function(
                        callee_name,
                        caller_file,
                        allowed_sources=allowed_sources,
                    )
                    if not callee_func:
                        continue
                    callee_file_hint = str(
                        callee_func.get("file_path") or callee_func.get("file") or ""
                    )
                callee_key = f"{callee_name}\0{callee_file_hint}"
                if not callee_name or callee_key in reachable:
                    continue
                callee_file = self._resolve_source_path(callee_file_hint)
                if allowed_sources is not None and (
                    not callee_file or callee_file not in allowed_sources
                ):
                    continue
                if callee_file:
                    selected_sources.add(callee_file)
                queue.append((callee_name, depth + 1, callee_file_hint))

        logger.info(
            "SVF reachable sources: completed processed=%d reachable=%d selected_sources=%d unresolved=%d",
            processed,
            len(reachable),
            len(selected_sources),
            len(unresolved),
        )
        return {item.split("\0", 1)[0] for item in reachable}, selected_sources, unresolved

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

    def _expand_symbol_closure(
        self,
        selected_bcs: Set[Path],
        all_bcs: Sequence[Path],
        bc_to_src: Mapping[Path, Path],
    ) -> Set[Path]:
        providers: Dict[str, List[Path]] = {}
        logger.info(
            "SVF symbol closure: scanning symbols for %d/%d selected .bc file(s)",
            len(selected_bcs),
            len(all_bcs),
        )
        pool_by_bc = self._pool_by_bc(all_bcs, bc_to_src)
        for idx, bc in enumerate(all_bcs, start=1):
            if idx == 1 or idx % 100 == 0 or idx == len(all_bcs):
                logger.info(
                    "SVF symbol closure: scanned symbol providers %d/%d",
                    idx,
                    len(all_bcs),
                )
            symbols = self._read_symbols_cached(self._symbol_cache, bc)
            for symbol in symbols.defined:
                providers.setdefault(symbol, []).append(Path(bc).resolve())

        added: Set[Path] = set()
        changed = True
        iteration = 0
        while changed:
            changed = False
            iteration += 1
            unresolved_symbols: Set[str] = set()
            for bc in list(selected_bcs):
                symbols = self._read_symbols_cached(self._symbol_cache, bc)
                unresolved_symbols.update(symbols.undefined)

            defined_in_selection: Set[str] = set()
            for bc in selected_bcs:
                defined_in_selection.update(
                    self._read_symbols_cached(self._symbol_cache, bc).defined
                )

            before_count = len(selected_bcs)
            for symbol in sorted(unresolved_symbols - defined_in_selection):
                provider_bcs = [
                    provider
                    for provider in providers.get(symbol, [])
                    if provider not in selected_bcs
                ]
                for provider in self._allowed_symbol_providers(
                    provider_bcs,
                    selected_bcs,
                    pool_by_bc,
                ):
                    selected_bcs.add(provider)
                    added.add(provider)
                    changed = True
            if changed:
                logger.info(
                    "SVF symbol closure: iteration %d added %d .bc file(s), selected=%d",
                    iteration,
                    len(selected_bcs) - before_count,
                    len(selected_bcs),
                )

        logger.info(
            "SVF symbol closure: completed with %d added .bc file(s)",
            len(added),
        )
        return added

    def _allowed_symbol_providers(
        self,
        provider_bcs: Sequence[Path],
        selected_bcs: Set[Path],
        pool_by_bc: Mapping[Path, str],
    ) -> List[Path]:
        if not provider_bcs:
            return []
        if not self.pool_classifier.enabled:
            return [Path(provider_bcs[0]).resolve()]
        selected_pools = {
            pool_by_bc.get(Path(bc).resolve(), "")
            for bc in selected_bcs
            if pool_by_bc.get(Path(bc).resolve(), "")
        }
        if selected_pools:
            return [
                Path(provider).resolve()
                for provider in provider_bcs
                if not pool_by_bc.get(Path(provider).resolve(), "")
                or pool_by_bc.get(Path(provider).resolve(), "") in selected_pools
            ][:1]
        return [
            Path(provider).resolve()
            for provider in provider_bcs
            if not pool_by_bc.get(Path(provider).resolve(), "")
        ][:1]

    def _read_symbols_cached(
        self,
        cache: Dict[Path, BitcodeSymbols],
        bc_path: Path,
    ) -> BitcodeSymbols:
        if bc_path not in cache:
            cache[bc_path] = self.symbol_reader.read_symbols(bc_path)
        return cache[bc_path]

    def _get_function(self, name: str, file_hint: str = "") -> Optional[Dict[str, Any]]:
        key = (name, file_hint)
        if key not in self._function_cache:
            try:
                func = (
                    self.db.get_function(name, file_path=file_hint)
                    if file_hint
                    else self.db.get_function(name)
                )
            except TypeError:
                func = self.db.get_function(name)
            self._function_cache[key] = dict(func) if func else None
        return self._function_cache[key]

    def _get_callees(self, name: str, caller_file: str) -> List[Dict[str, Any]]:
        key = (name, caller_file)
        if key not in self._callees_cache:
            try:
                callees = self.db.get_callees(name, limit=10000, caller_file=caller_file)
            except TypeError:
                callees = self.db.get_callees(name, limit=10000)
            self._callees_cache[key] = [dict(callee) for callee in callees]
        return self._callees_cache[key]

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
        *,
        normalized_bc_to_src: Optional[Mapping[Path, Path]] = None,
    ) -> Dict[Path, List[Path]]:
        normalized_map = (
            normalized_bc_to_src
            if normalized_bc_to_src is not None
            else self._normalize_bc_to_src(bc_to_src)
        )
        result: Dict[Path, List[Path]] = {}
        for bc in all_bcs:
            src = normalized_map.get(Path(bc).resolve())
            if src:
                result.setdefault(src, []).append(Path(bc).resolve())
        return result

    def _normalize_bc_to_src(self, bc_to_src: Mapping[Path, Path]) -> Dict[Path, Path]:
        normalized: Dict[Path, Path] = {}
        for bc, src in bc_to_src.items():
            source = self._resolve_source_path(str(src))
            if source:
                normalized[Path(bc).resolve()] = source
        return normalized

    def _resolve_source_path(self, file_path: str) -> Optional[Path]:
        if not file_path:
            return None
        raw = Path(file_path)
        candidates = (
            [raw] if raw.is_absolute() else [self.source_root / raw, self.project_root / raw]
        )
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
            file_path = str(getattr(entry, "file_path", "") or "")
            seen_key = f"{name}\0{file_path}"
            if seen_key in seen:
                continue
            seen.add(seen_key)
            records.append(
                {
                    "name": name,
                    "file_path": file_path,
                }
            )
        return records

    @staticmethod
    def _ordered_subset(all_bcs: Sequence[Path], selected_bcs: Set[Path]) -> List[Path]:
        selected = {Path(p).resolve() for p in selected_bcs}
        return [Path(bc).resolve() for bc in all_bcs if Path(bc).resolve() in selected]

    @staticmethod
    def _paths_to_bitset(paths: Iterable[Path], path_to_bit: Mapping[Path, int]) -> int:
        bits = 0
        for path in paths:
            bit = path_to_bit.get(Path(path).resolve())
            if bit is not None:
                bits |= 1 << bit
        return bits

    @staticmethod
    def _iter_bit_indices(bits: int) -> Iterable[int]:
        while bits:
            low_bit = bits & -bits
            yield low_bit.bit_length() - 1
            bits ^= low_bit

    @staticmethod
    def _entry_cluster_cost_bias(sizes: Sequence[int]) -> float:
        if not sizes:
            return 1.0
        ordered = sorted(size for size in sizes if size >= 0)
        if not ordered:
            return 1.0
        mid = len(ordered) // 2
        if len(ordered) % 2:
            return float(max(1, ordered[mid]))
        return float(max(1.0, (ordered[mid - 1] + ordered[mid]) / 2))

    @staticmethod
    def _entry_cluster_cost(size: int, cost_bias: float) -> float:
        return cost_bias + (size * size)

    @classmethod
    def _entry_cluster_total_cost(
        cls,
        clusters: Iterable[Mapping[str, Any]],
        cost_bias: float,
    ) -> float:
        return sum(
            cls._entry_cluster_cost(int(cluster["selected_size"]), cost_bias)
            for cluster in clusters
        )

    @staticmethod
    def _entry_cluster_size_summary(sizes: Sequence[int]) -> str:
        if not sizes:
            return "min=0,p50=0,p95=0,max=0"
        ordered = sorted(sizes)
        p50 = ordered[len(ordered) // 2]
        p95_idx = min(len(ordered) - 1, max(0, ((95 * len(ordered)) - 1) // 100))
        return f"min={ordered[0]},p50={p50}," f"p95={ordered[p95_idx]},max={ordered[-1]}"

    @staticmethod
    def _jaccard(left: Set[Path], right: Set[Path]) -> float:
        if not left and not right:
            return 1.0
        union = left | right
        return (len(left & right) / len(union)) if union else 0.0

    def _best_callee_function(
        self,
        callee_name: str,
        caller_file: str,
        *,
        allowed_sources: Optional[Set[Path]] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            candidates = self._get_functions_by_name(callee_name)
            if allowed_sources is not None:
                candidates = [
                    candidate
                    for candidate in candidates
                    if (
                        self._resolve_source_path(
                            str(candidate.get("file_path") or candidate.get("file") or "")
                        )
                        in allowed_sources
                    )
                ]
            if candidates:
                return min(
                    candidates,
                    key=lambda candidate: self._path_distance(
                        caller_file,
                        str(candidate.get("file_path") or candidate.get("file") or ""),
                    ),
                )
            return self.db.get_function(callee_name)
        except TypeError:
            return self.db.get_function(callee_name)

    def _get_functions_by_name(self, name: str) -> List[Dict[str, Any]]:
        if name not in self._functions_by_name_cache:
            get_candidates = getattr(self.db, "get_functions_by_name", None)
            candidates = get_candidates(name) if callable(get_candidates) else []
            self._functions_by_name_cache[name] = [dict(candidate) for candidate in candidates]
        return self._functions_by_name_cache[name]

    @staticmethod
    def _path_distance(left: str, right: str) -> tuple[int, str]:
        left_parts = Path(str(left or "").replace("\\", "/")).parts
        right_parts = Path(str(right or "").replace("\\", "/")).parts
        common = 0
        for left_part, right_part in zip(left_parts, right_parts):
            if left_part != right_part:
                break
            common += 1
        return (max(len(left_parts), len(right_parts)) - common, str(right))

    @staticmethod
    def _safe_group_suffix(value: str) -> str:
        cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value))
        return cleaned.strip("._-") or "entry"

    def _format_paths(self, paths: Iterable[Path]) -> List[str]:
        formatted: List[str] = []
        for path in sorted({Path(p).resolve() for p in paths}, key=lambda p: p.as_posix()):
            try:
                formatted.append(path.relative_to(self.project_root).as_posix())
            except ValueError:
                formatted.append(path.as_posix())
        return formatted
