"""
Clang-SQLite backend - implements CodeBackend using clangd LSP + KnowledgeDB.
Provides precise C/C++ code structure extraction without Joern dependency.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .backend_base import CodeBackend
from .clang_extractor import ClangExtractor
from .clang_extractor_pool import ClangExtractorPool
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)


class ClangBackend(CodeBackend):
    """
    基于 clangd LSP + SQLite 的代码分析后端。
    使用 ClangExtractor 批量提取代码结构，存入 KnowledgeDB 供查询。
    """

    MACRO_EXTRACTOR_VERSION = "2"
    SYMBOL_CONTEXT_EXTRACTOR_VERSION = "6"
    TYPE_EXTRACTOR_VERSION = "1"
    FUNCTION_TYPE_REF_EXTRACTOR_VERSION = "7"
    FUNCTION_SYMBOL_CONTEXT_INDEX = "function_symbol_context"
    FUNCTION_TYPE_REFS_INDEX = "function_type_refs"

    def __init__(
        self,
        clangd_path: str = "clangd",
        db_path: str = ".zscope_knowledge/code_knowledge.db",
        batch_size: int = 50,
        max_threads: int = 4,
        frontend: str = "auto",
        clang_indexer_path: str = "zscope-clang-indexer",
    ):
        if frontend not in {"auto", "batch", "lsp"}:
            raise ValueError("clang frontend must be auto, batch, or lsp")
        self._frontend = frontend
        self._clang_indexer_path = clang_indexer_path
        self._clangd_path = clangd_path
        self._db_path = db_path
        self._batch_size = batch_size
        self._max_threads = max_threads
        self._extractor: Optional[Union[ClangExtractor, ClangExtractorPool]] = None
        self._db: Optional[KnowledgeDB] = None
        self._status = "idle"
        self._source_path: Optional[Path] = None
        self._include_paths: List[Path] = []
        self._exclude_paths: List[Path] = []
        self._type_ref_scheduler: Any = None
        self._compile_preparation: Any = None
        self._compile_commands_path: Optional[str] = None
        self._compile_generation_started = False
        self._compile_preparation_tools: Dict[str, Any] = {}

    @property
    def db(self) -> Optional[KnowledgeDB]:
        return self._db

    # ── 生命周期 ──

    def initialize(self, source_path: str, **kwargs) -> bool:
        """初始化 clangd + SQLite 后端。"""
        project_root = kwargs.get("project_root", source_path)
        self._compile_commands_path = kwargs.get("compile_commands_path")
        self._compile_preparation = kwargs.get("compile_preparation")
        self._compile_generation_started = False
        self._compile_preparation_tools = kwargs.get("compile_preparation_tools", {})
        wait = kwargs.get("wait", True)

        self._source_path = Path(source_path).absolute()
        project_root = Path(project_root).absolute() if project_root else self._source_path

        self._include_paths = [Path(p).absolute() for p in (kwargs.get("include_paths", []) or [])]
        self._exclude_paths = [Path(p).absolute() for p in (kwargs.get("exclude_paths", []) or [])]

        # 初始化 SQLite 知识库（存储在 project_root）
        db_full_path = project_root / self._db_path
        self._db = KnowledgeDB(str(db_full_path))

        self._status = "building"

        if wait:
            return self._run_full_extraction()
        else:
            import threading

            t = threading.Thread(target=self._run_full_extraction, daemon=True)
            t.start()
            return True

    def _ensure_extractor(self) -> bool:
        """按需启动 clangd 提取器（仅在有文件需要提取时调用）。"""
        if self._extractor is not None:
            health_check = getattr(self._extractor, "is_healthy", None)
            if not callable(health_check) or bool(health_check()):
                return True
            logger.warning("Restarting an unhealthy clangd extractor")
            try:
                self._extractor.stop()
            finally:
                self._extractor = None
        if self._source_path is None:
            return False
        cc_dir = Path(self._compile_commands_path).parent if self._compile_commands_path else None
        shard_count = ClangExtractorPool.shard_count_from_env()
        if shard_count > 1:
            logger.info(
                "Using %d clangd shards for base extraction (max_threads=%d)",
                shard_count,
                self._max_threads,
            )
            self._extractor = ClangExtractorPool(
                project_root=self._source_path,  # clangd cwd/rootUri = source_root
                clangd_path=self._clangd_path,
                compile_commands_dir=cc_dir,
                max_threads=self._max_threads,
                shard_count=shard_count,
            )
        else:
            self._extractor = ClangExtractor(
                project_root=self._source_path,  # clangd cwd/rootUri = source_root
                clangd_path=self._clangd_path,
                compile_commands_dir=cc_dir,
                max_threads=self._max_threads,
            )
        receipt = self._compile_preparation
        if receipt is not None:
            receipt.validate()
            for shard in getattr(self._extractor, "_shards", [self._extractor]):
                shard._compile_preparation = receipt
        if not self._extractor.start():
            logger.error("Failed to start clangd extractor")
            return False
        return True

    def _run_full_extraction(self) -> bool:
        # A base refresh owns publication exclusively. Stop continuations before
        # replacing their function/type IDs, then start a new generation owner.
        self._stop_type_ref_scheduler()
        with self.pause_type_references():
            if self._compile_generation_started:
                # This explicit refresh starts a new generation after all old
                # continuations stop. Deferred SVF never enters this branch.
                self._compile_preparation = None
            self._compile_generation_started = True
            result = self._run_full_extraction_impl()
        if (
            result
            and self._frontend == "auto"
            and self._db is not None
            and self._db.get_metadata("clang_fact_frontend") == "batch"
        ):
            from .clang_type_state import FALLBACK_KEY
            import json

            if json.loads(self._db.get_metadata(FALLBACK_KEY) or "{}"):
                from .clang_type_scheduler import acquire_scheduler
                from .clang_type_state import counts

                logger.info(
                    "[function-type-refs] handoff origin=batch_fallback mode=background "
                    "query_ready=true functions=%s",
                    counts(self._db),
                )
                self._type_ref_scheduler = acquire_scheduler(self)
        return result

    def _stop_type_ref_scheduler(self) -> None:
        scheduler = getattr(self, "_type_ref_scheduler", None)
        if scheduler is not None:
            from .clang_type_scheduler import release_scheduler

            release_scheduler(scheduler)
            self._type_ref_scheduler = None

    def settle_type_references(self, *, timeout_seconds: float = 300.0) -> Dict[str, Any]:
        """Publish all pending function type facts before receipt freezing."""

        scheduler = getattr(self, "_type_ref_scheduler", None)
        if scheduler is None:
            return {"status": "not_required"}
        result = scheduler.drain_background(timeout_seconds=timeout_seconds)
        return {"status": "complete", **result}

    def pause_type_references(self) -> Any:
        from .clang_type_scheduler import pause_registered_scheduler

        return pause_registered_scheduler(self._db)

    def _run_full_extraction_impl(self) -> bool:
        """Refresh base TU facts, then independently refresh derived indexes."""
        try:
            if self._compile_commands_path:
                if self._compile_preparation is None:
                    from .compile_commands_prepare import prepare_compile_commands
                    from .compile_preflight import discover_tools

                    self._compile_preparation = prepare_compile_commands(
                        Path(self._compile_commands_path),
                        discover_tools(
                            indexer=self._clang_indexer_path if self._frontend != "lsp" else "",
                            clangd=self._clangd_path,
                            **self._compile_preparation_tools,
                        ),
                        workers=self._max_threads,
                    )
                else:
                    self._compile_preparation.validate()
            if self._frontend != "lsp":
                from .clang_batch import BatchIndexer, find_indexer

                native = find_indexer(self._clang_indexer_path)
                if not native and self._clang_indexer_path != "zscope-clang-indexer":
                    raise RuntimeError(
                        "Selected batch indexer is missing or incompatible: "
                        + self._clang_indexer_path
                    )
                if native and self._compile_commands_path and self._db is not None:
                    complete = BatchIndexer(self, *native).run()
                    self._status = "ready" if complete else "error"
                    return complete
                if self._frontend == "batch":
                    raise RuntimeError(
                        "batch frontend requires a compatible zscope-clang-indexer and compile_commands.json"
                    )
                logger.info(
                    "[clang-frontend] batch tool or compilation database unavailable; using LSP"
                )
            file_list = self._collect_source_files()
            from .clang_extractor import ClangExtractor

            if self._db is None:
                self._status = "error"
                return False

            db = self._db
            if self._metadata_value(db, "clang_fact_frontend") == "batch":
                return self._transition_to_lsp(db)
            source_root = self._source_path
            existing_tus = list(db.get_all_tus())
            macro_version = self._metadata_value(db, "macro_extractor_version")
            type_version = self._metadata_value(db, "type_extractor_version")

            def normalize_db_path(path_value: str) -> str:
                p = Path(str(path_value))
                if not p.is_absolute() and source_root is not None:
                    p = source_root / p
                return str(p.resolve())

            current_files: Dict[str, Path] = {
                normalize_db_path(str(fp)): fp.resolve() for fp in file_list
            }
            existing_tus_by_path = {
                normalize_db_path(str(tu.get("file_path") or "")): tu
                for tu in existing_tus
                if str(tu.get("file_path") or "")
            }
            deleted_tus = [
                tu
                for tu in existing_tus
                if normalize_db_path(str(tu.get("file_path") or "")) not in current_files
            ]
            file_hashes: Dict[str, str] = {}
            if file_list:
                from concurrent.futures import ThreadPoolExecutor

                resolved_files = [Path(fp).resolve() for fp in file_list]
                hash_workers = min(
                    max(1, int(self._max_threads or 1)),
                    8,
                    len(resolved_files),
                )
                if hash_workers == 1:
                    hashes = map(ClangExtractor._compute_file_hash, resolved_files)
                    file_hashes = {str(path): value for path, value in zip(resolved_files, hashes)}
                else:
                    with ThreadPoolExecutor(
                        max_workers=hash_workers,
                        thread_name_prefix="ClangHash",
                    ) as executor:
                        file_hashes = {
                            str(path): value
                            for path, value in zip(
                                resolved_files,
                                executor.map(
                                    ClangExtractor._compute_file_hash,
                                    resolved_files,
                                ),
                            )
                        }
            deferred_tu_commits = bool(getattr(db, "SUPPORTS_DEFERRED_TU_COMMITS", False))
            force_refresh_paths: set[str] = set()
            # Read the previous include graph before deleting or replacing facts.
            # A TU's own bytes can be unchanged while an included header changes
            # its functions, macros, types and call edges.
            changed_paths = {
                path
                for path, tu in existing_tus_by_path.items()
                if path not in file_hashes
                or file_hashes[path] != str(tu.get("file_hash") or "")
                or tu.get("status") != "indexed"
            }
            changed_paths.update(set(current_files) - set(existing_tus_by_path))
            if changed_paths and existing_tus:
                closures = db.get_transitive_include_closures(current_files)
                for source, dependencies in closures.items():
                    if any(normalize_db_path(path) in changed_paths for path in dependencies):
                        force_refresh_paths.add(normalize_db_path(source))
            compile_context = ""
            if self._compile_preparation is not None:
                import json
                from .indexing_identity import digest_json

                receipt = self._compile_preparation
                compile_context = digest_json(
                    [
                        receipt.effective_digest,
                        receipt.dependencies_json,
                        [
                            tool
                            for tool in json.loads(receipt.tools_json)
                            if tool["name"] == "clangd"
                        ],
                    ]
                )
                previous = db.get_metadata("clang_prepared_lsp_context")
                if (previous and previous != compile_context) or (
                    not previous and receipt.effective_digest != receipt.original_digest
                ):
                    force_refresh_paths.update(current_files)
            deleted_paths: List[Path] = []
            changed_count = 0
            prescanned_tus: Dict[str, Tuple[int, bool]] = {}
            try:
                for tu in deleted_tus:
                    tu_id = int(tu["id"])
                    if deferred_tu_commits:
                        impact = db.delete_tu(tu_id, commit=False)
                    else:
                        impact = db.delete_tu(tu_id)
                    raw_path = str(tu.get("file_path") or "")
                    if raw_path:
                        deleted_paths.append(Path(normalize_db_path(raw_path)))
                    for related in impact.get("related_files", []):
                        related_key = normalize_db_path(str(related))
                        related_path = current_files.get(related_key)
                        if related_path is not None and self._is_path_allowed(related_path):
                            force_refresh_paths.add(related_key)

                for fp in file_list:
                    fp = fp.resolve()
                    file_hash = file_hashes[str(fp)]
                    existing_tu = existing_tus_by_path.get(normalize_db_path(str(fp)))
                    registered_path = (
                        str(existing_tu.get("file_path") or str(fp))
                        if existing_tu is not None
                        else str(fp)
                    )
                    if deferred_tu_commits:
                        tu_id, changed = db.register_tu_hash(
                            registered_path,
                            file_hash,
                            commit=False,
                        )
                    else:
                        tu_id, changed = db.register_tu_hash(registered_path, file_hash)
                    if not changed and normalize_db_path(str(fp)) in force_refresh_paths:
                        changed = True
                        if deferred_tu_commits:
                            db.mark_tu_pending(tu_id, commit=False)
                        else:
                            db.mark_tu_pending(tu_id)
                    prescanned_tus[str(fp)] = (tu_id, changed)
                    if changed:
                        changed_count += 1

                base_version_missing = not macro_version or not type_version
                explicit_base_version_mismatch = bool(
                    (macro_version and macro_version != self.MACRO_EXTRACTOR_VERSION)
                    or (type_version and type_version != self.TYPE_EXTRACTOR_VERSION)
                )
                can_confirm_v14_base = self._can_confirm_v14_base_facts(
                    db,
                    existing_tus=existing_tus,
                    current_files=current_files,
                    prescanned_tus=prescanned_tus,
                    deleted_tus=deleted_tus,
                    base_version_missing=base_version_missing,
                    explicit_base_version_mismatch=explicit_base_version_mismatch,
                    source_root=source_root,
                )
                if can_confirm_v14_base:
                    logger.info(
                        "Incremental: confirmed schema-v14 base facts for %d unchanged TUs",
                        len(file_list),
                    )
                    self._mark_base_indexes_current(
                        db,
                        commit=not deferred_tu_commits,
                    )
                    macro_version = self.MACRO_EXTRACTOR_VERSION
                    type_version = self.TYPE_EXTRACTOR_VERSION

                force_macro_refresh = macro_version != self.MACRO_EXTRACTOR_VERSION
                force_type_refresh = type_version != self.TYPE_EXTRACTOR_VERSION

                if force_macro_refresh or force_type_refresh:
                    for file_path, (tu_id, changed) in list(prescanned_tus.items()):
                        if not changed:
                            if deferred_tu_commits:
                                db.mark_tu_pending(tu_id, commit=False)
                            else:
                                db.mark_tu_pending(tu_id)
                            prescanned_tus[file_path] = (tu_id, True)
                            changed_count += 1

                base_facts_changed = bool(deleted_tus or changed_count)
                if base_facts_changed:
                    if deferred_tu_commits:
                        db.mark_derived_indexes_dirty(
                            reason="base_facts_changed",
                            commit=False,
                        )
                    else:
                        db.mark_derived_indexes_dirty(reason="base_facts_changed")
                if deferred_tu_commits:
                    db.commit()
            except BaseException:
                if deferred_tu_commits:
                    db.rollback()
                raise

            derived_work = self._derived_indexes_needing_rebuild(db)
            needs_clangd = bool(file_list) and bool(changed_count or derived_work)
            extractor: Optional[Union[ClangExtractor, ClangExtractorPool]] = None
            index_ready = False
            supports_deferred_index_barrier = False
            if needs_clangd:
                if not self._ensure_extractor():
                    self._status = "error"
                    return False
                extractor = self._extractor
                if extractor is None:
                    self._status = "error"
                    return False
                seed_project_files = getattr(extractor, "seed_project_file_index", None)
                if callable(seed_project_files):
                    seed_project_files(file_list)
                if deleted_paths and hasattr(extractor, "notify_files_deleted"):
                    extractor.notify_files_deleted(deleted_paths)
                supports_deferred_index_barrier = isinstance(
                    extractor, (ClangExtractor, ClangExtractorPool)
                )
                if not supports_deferred_index_barrier and not extractor.wait_for_indexing(
                    timeout=120, idle_threshold=3.0
                ):
                    logger.warning(
                        "clangd indexing did not become ready before the soft timeout; "
                        "continuing with a partially indexed project"
                    )
                index_ready = not supports_deferred_index_barrier

            def wait_for_index_once() -> bool:
                nonlocal index_ready
                if index_ready:
                    return True
                if extractor is None:
                    return False
                index_ready = bool(extractor.wait_for_indexing(timeout=120, idle_threshold=3.0))
                if not index_ready:
                    logger.warning(
                        "clangd indexing did not become ready before the soft timeout; "
                        "continuing with a partially indexed project"
                    )
                    index_ready = True
                return index_ready

            if changed_count:
                assert extractor is not None
                logger.info(
                    "Incremental: %d/%d TUs require base extraction",
                    changed_count,
                    len(file_list),
                )
                if supports_deferred_index_barrier:
                    stats = extractor.run_batch_extraction(
                        file_list,
                        db,
                        batch_size=self._batch_size,
                        prescanned_tus=prescanned_tus,
                        index_barrier=wait_for_index_once,
                    )
                else:
                    stats = extractor.run_batch_extraction(
                        file_list,
                        db,
                        batch_size=self._batch_size,
                        prescanned_tus=prescanned_tus,
                    )
                logger.info(
                    "Base extraction complete: %d extracted, %d skipped, %d failed",
                    stats["success"],
                    stats["skipped"],
                    stats["failed"],
                )
                if int(stats.get("failed") or 0):
                    logger.error(
                        "Base extraction incomplete; derived indexes remain dirty failed_tus=%d",
                        int(stats.get("failed") or 0),
                    )
                    self._status = "error"
                    return False
                # Base versions become durable before either derived rebuild starts.
                self._mark_base_indexes_current(db)
            elif deleted_tus or not file_list:
                # Deletes were already applied transactionally by KnowledgeDB.  An empty
                # project has a valid empty base index and never needs clangd.
                if not file_list and force_macro_refresh:
                    clear_macros = getattr(db, "clear_macro_definitions", None)
                    if callable(clear_macros):
                        clear_macros()
                self._mark_base_indexes_current(db)
            elif force_macro_refresh or force_type_refresh:
                # This is only reachable for a zero-TU base refresh.
                self._mark_base_indexes_current(db)
            else:
                logger.info(
                    "Incremental: all %d TUs unchanged, reusing cached base facts",
                    len(file_list),
                )

            # Base extraction may have dirtied otherwise-current derived indexes.
            derived_work = self._derived_indexes_needing_rebuild(db)
            partial_only_files: Optional[Set[str]] = None
            if derived_work:
                partial_only_files = self._plan_partial_derived_rebuild(
                    db,
                    derived_work,
                    changed_paths=[
                        path for path, (_tu_id, changed) in prescanned_tus.items() if changed
                    ],
                    deleted_paths=[str(path) for path in deleted_paths],
                )
            if derived_work and file_list and not wait_for_index_once():
                self._status = "error"
                return False
            derived_failed = False
            begin_session = getattr(extractor, "begin_derived_rebuild_session", None)
            end_session = getattr(extractor, "end_derived_rebuild_session", None)
            session_started = False
            try:
                if derived_work and extractor is not None and callable(begin_session):
                    begin_session()
                    session_started = True
                combined_rebuild = getattr(extractor, "rebuild_function_derived_refs", None)
                combined_names = {item[0] for item in derived_work}
                use_combined = bool(
                    file_list
                    and extractor is not None
                    and callable(combined_rebuild)
                    and combined_names
                    == {
                        self.FUNCTION_SYMBOL_CONTEXT_INDEX,
                        self.FUNCTION_TYPE_REFS_INDEX,
                    }
                )
                if use_combined:
                    assert callable(combined_rebuild)
                    started_specs: List[Tuple[str, str, Any]] = []
                    try:
                        for spec in derived_work:
                            index_name, target_version, _rebuild_method = spec
                            db.begin_derived_index_rebuild(index_name, target_version)
                            started_specs.append(spec)
                            db.prepare_derived_index_staging(index_name)
                        if partial_only_files is not None:
                            combined_result = combined_rebuild(
                                db, use_staging=True, only_files=partial_only_files
                            )
                        else:
                            combined_result = combined_rebuild(db, use_staging=True)
                        if self._compile_preparation is not None:
                            self._compile_preparation.validate()
                        counts = dict(combined_result.get("counts") or {})
                        errors = dict(combined_result.get("errors") or {})
                        for index_name, target_version, _rebuild_method in derived_work:
                            error = errors.get(index_name)
                            if error is not None:
                                derived_failed = True
                                exc = (
                                    error
                                    if isinstance(error, Exception)
                                    else RuntimeError(str(error))
                                )
                                self._record_derived_failure(
                                    db,
                                    extractor,
                                    index_name,
                                    target_version,
                                    exc,
                                )
                                continue
                            row_count = int(counts.get(index_name) or 0)
                            stats_getter = getattr(
                                extractor,
                                "get_last_derived_stats",
                                None,
                            )
                            last_stats = (
                                stats_getter(index_name)
                                if callable(stats_getter)
                                else {"rows": row_count}
                            )
                            try:
                                if partial_only_files is not None:
                                    db.finalize_derived_index_rebuild(
                                        index_name,
                                        target_version,
                                        last_stats,
                                        merge_files=sorted(partial_only_files),
                                    )
                                else:
                                    db.finalize_derived_index_rebuild(
                                        index_name,
                                        target_version,
                                        last_stats,
                                    )
                            except Exception as exc:
                                derived_failed = True
                                self._record_derived_failure(
                                    db,
                                    extractor,
                                    index_name,
                                    target_version,
                                    exc,
                                )
                            else:
                                logger.info(
                                    "Rebuilt derived index %s rows=%d (combined pass)",
                                    index_name,
                                    row_count,
                                )
                    except Exception as exc:
                        derived_failed = True
                        for index_name, target_version, _method in started_specs or derived_work:
                            self._record_derived_failure(
                                db,
                                extractor,
                                index_name,
                                target_version,
                                exc,
                            )
                else:
                    for index_name, target_version, rebuild_method in derived_work:
                        try:
                            db.begin_derived_index_rebuild(index_name, target_version)
                            db.prepare_derived_index_staging(index_name)
                            if file_list:
                                if extractor is None:
                                    raise RuntimeError(
                                        "clangd extractor unavailable for derived rebuild"
                                    )
                                if partial_only_files is not None:
                                    row_count = int(
                                        rebuild_method(
                                            extractor,
                                            db,
                                            use_staging=True,
                                            only_files=partial_only_files,
                                        )
                                    )
                                else:
                                    row_count = int(rebuild_method(extractor, db, use_staging=True))
                                stats_getter = getattr(
                                    extractor,
                                    "get_last_derived_stats",
                                    None,
                                )
                                last_stats = (
                                    stats_getter(index_name)
                                    if callable(stats_getter)
                                    else {"rows": row_count}
                                )
                            else:
                                row_count = 0
                                last_stats = {"rows": 0, "files": 0, "functions": 0}
                            if self._compile_preparation is not None:
                                self._compile_preparation.validate()
                            if partial_only_files is not None:
                                db.finalize_derived_index_rebuild(
                                    index_name,
                                    target_version,
                                    last_stats,
                                    merge_files=sorted(partial_only_files),
                                )
                            else:
                                db.finalize_derived_index_rebuild(
                                    index_name,
                                    target_version,
                                    last_stats,
                                )
                            logger.info(
                                "Rebuilt derived index %s rows=%d",
                                index_name,
                                row_count,
                            )
                        except Exception as exc:
                            derived_failed = True
                            self._record_derived_failure(
                                db,
                                extractor,
                                index_name,
                                target_version,
                                exc,
                            )
            finally:
                if session_started and callable(end_session):
                    end_session()

            if derived_failed or not self._derived_indexes_are_current(db):
                self._status = "error"
                return False
            if self._compile_preparation is not None:
                self._compile_preparation.validate()
                db.set_metadata("clang_prepared_lsp_context", compile_context)
            db.set_metadata("clang_fact_frontend", "lsp")
            self._status = "ready"
            return True
        except Exception as e:
            logger.error("Extraction failed: %s", e)
            self._status = "error"
            return False
        finally:
            # All public query methods below are SQLite-backed.  Releasing clangd
            # after the build avoids retaining the project's AST/preamble cache for
            # the rest of a long-running scan; a later refresh restarts it on demand.
            extractor = self._extractor
            health_check = getattr(extractor, "is_healthy", None)
            stop = getattr(extractor, "stop", None)
            if callable(health_check) and callable(stop):
                try:
                    stop()
                except Exception as stop_exc:
                    logger.debug("Failed to stop clangd after extraction: %s", stop_exc)
                finally:
                    if self._extractor is extractor:
                        self._extractor = None

    def _transition_to_lsp(self, published: KnowledgeDB) -> bool:
        """Changing frontend must rebuild, including unchanged source files."""
        import sqlite3
        import tempfile
        from .clang_batch import publish_staged_database
        from .indexing_runtime import heartbeat

        previous_frontend = self._frontend
        with (
            heartbeat("clang-frontend-transition"),
            tempfile.TemporaryDirectory(
                prefix="clang-lsp-transition-", dir=str(Path(published._db_path).parent)
            ) as directory,
        ):
            path = Path(directory) / "stage.sqlite3"
            with sqlite3.connect(str(path)) as target:
                published._conn.backup(target)
            stage = KnowledgeDB(str(path))
            try:
                setattr(stage, "_derived_cache_owner_path", published._db_path)
                for tu in stage.get_all_tus():
                    stage.mark_tu_pending(int(tu["id"]), commit=False)
                stage._conn.execute(
                    "UPDATE metadata SET value='' WHERE key LIKE 'clang_batch_base:%' OR key='clang_batch_input'"
                )
                stage.set_metadata("clang_fact_frontend", "lsp", commit=False)
                stage._conn.execute("DELETE FROM compilation_facts")
                stage._conn.execute("DELETE FROM compilation_instances")
                stage.mark_derived_indexes_dirty(reason="compiler_frontend_changed", commit=False)
                stage.commit()
                self._db, self._frontend = stage, "lsp"
                if not self._run_full_extraction():
                    return False
                publish_staged_database(published, path)
                return True
            finally:
                self._db, self._frontend = published, previous_frontend
                stage.close()

    @staticmethod
    def _metadata_value(db: Any, key: str) -> str:
        get_metadata = getattr(db, "get_metadata", None)
        if not callable(get_metadata):
            return ""
        try:
            return str(get_metadata(key) or "")
        except Exception:
            return ""

    def _mark_macro_index_current(self, db: Any, *, commit: bool = True) -> None:
        set_metadata = getattr(db, "set_metadata", None)
        if callable(set_metadata):
            if bool(getattr(db, "SUPPORTS_DEFERRED_TU_COMMITS", False)):
                set_metadata(
                    "macro_extractor_version",
                    self.MACRO_EXTRACTOR_VERSION,
                    commit=commit,
                )
            else:
                set_metadata("macro_extractor_version", self.MACRO_EXTRACTOR_VERSION)

    def _mark_type_index_current(self, db: Any, *, commit: bool = True) -> None:
        set_metadata = getattr(db, "set_metadata", None)
        if callable(set_metadata):
            if bool(getattr(db, "SUPPORTS_DEFERRED_TU_COMMITS", False)):
                set_metadata(
                    "type_extractor_version",
                    self.TYPE_EXTRACTOR_VERSION,
                    commit=commit,
                )
            else:
                set_metadata("type_extractor_version", self.TYPE_EXTRACTOR_VERSION)

    def _mark_base_indexes_current(self, db: Any, *, commit: bool = True) -> None:
        deferred = bool(getattr(db, "SUPPORTS_DEFERRED_TU_COMMITS", False))
        self._mark_macro_index_current(db, commit=False if deferred else commit)
        self._mark_type_index_current(db, commit=False if deferred else commit)
        if deferred and commit:
            db.commit()

    def _can_confirm_v14_base_facts(
        self,
        db: Any,
        *,
        existing_tus: List[Dict[str, Any]],
        current_files: Dict[str, Path],
        prescanned_tus: Dict[str, Tuple[int, bool]],
        deleted_tus: List[Dict[str, Any]],
        base_version_missing: bool,
        explicit_base_version_mismatch: bool,
        source_root: Optional[Path],
    ) -> bool:
        """One-time compatibility confirmation for pre-split schema-v14 caches."""
        if (
            not base_version_missing
            or explicit_base_version_mismatch
            or deleted_tus
            or not existing_tus
            or self._metadata_value(db, "schema_version")
            not in {"14", "15", KnowledgeDB.SCHEMA_VERSION}
        ):
            return False
        if any(str(tu.get("status") or "") != "indexed" for tu in existing_tus):
            return False
        existing_paths = set()
        for tu in existing_tus:
            path = Path(str(tu.get("file_path") or ""))
            if not path.is_absolute() and source_root is not None:
                path = source_root / path
            existing_paths.add(str(path.resolve()))
        if existing_paths != set(current_files):
            return False
        return bool(prescanned_tus) and not any(changed for _, changed in prescanned_tus.values())

    def _derived_indexes_needing_rebuild(
        self,
        db: Any,
    ) -> List[Tuple[str, str, Any]]:
        specs = (
            (
                self.FUNCTION_SYMBOL_CONTEXT_INDEX,
                self.SYMBOL_CONTEXT_EXTRACTOR_VERSION,
                lambda extractor, target_db, **kwargs: extractor.rebuild_function_symbol_refs(
                    target_db, **kwargs
                ),
            ),
            (
                self.FUNCTION_TYPE_REFS_INDEX,
                self.FUNCTION_TYPE_REF_EXTRACTOR_VERSION,
                lambda extractor, target_db, **kwargs: extractor.rebuild_function_type_refs(
                    target_db, **kwargs
                ),
            ),
        )
        return [spec for spec in specs if db.derived_index_needs_rebuild(spec[0], spec[1])]

    def _plan_partial_derived_rebuild(
        self,
        db: Any,
        derived_work: List[Tuple[str, str, Any]],
        *,
        changed_paths: List[str],
        deleted_paths: List[str],
    ) -> Optional[Set[str]]:
        """Scope the derived rebuild to include-closure-affected files.

        Partial rebuilds merge staged rows for the affected files only, so
        they run exclusively when every dirty index was invalidated by base
        facts (never by an extractor version bump, a purge-driven reason, or
        a previous failure) and the affected set stays small enough for the
        merge to beat a full rebuild.
        """
        if not (changed_paths or deleted_paths):
            return None
        compute = getattr(db, "compute_derived_affected_files", None)
        if not callable(compute):
            return None
        for index_name, _target_version, _rebuild_method in derived_work:
            state = db.get_derived_index_state(index_name)
            if str(state.get("dirty_reason") or "") != "base_facts_changed":
                return None
        get_functions = getattr(db, "get_function_records", None)
        if not callable(get_functions):
            return None
        try:
            candidates = sorted(
                {
                    str(row.get("file_path") or "")
                    for row in get_functions()
                    if str(row.get("file_path") or "")
                }
            )
            if not candidates:
                return None
            affected = compute(changed_paths, deleted_paths, candidates)
        except Exception as exc:
            logger.warning("Partial derived rebuild planning failed; using full rebuild: %s", exc)
            return None
        if affected is None:
            return None
        logger.info(
            "Partial derived rebuild: %d/%d function file(s) affected by base changes",
            len(affected),
            len(candidates),
        )
        return set(affected)

    def _derived_indexes_are_current(self, db: Any) -> bool:
        expected = (
            (self.FUNCTION_SYMBOL_CONTEXT_INDEX, self.SYMBOL_CONTEXT_EXTRACTOR_VERSION),
            (self.FUNCTION_TYPE_REFS_INDEX, self.FUNCTION_TYPE_REF_EXTRACTOR_VERSION),
        )
        for index_name, target_version in expected:
            state = db.get_derived_index_state(index_name)
            if (
                str(state.get("status") or "") != "current"
                or str(state.get("applied_version") or "") != target_version
            ):
                return False
        return True

    def _derived_indexes_ready_for_queries(self, db: Any) -> bool:
        if self._derived_indexes_are_current(db):
            return True
        symbol = db.get_derived_index_state(self.FUNCTION_SYMBOL_CONTEXT_INDEX)
        types = db.get_derived_index_state(self.FUNCTION_TYPE_REFS_INDEX)
        return bool(
            self._frontend == "auto"
            and db.get_metadata("clang_type_refs_generation")
            and symbol.get("status") == "current"
            and symbol.get("applied_version") == self.SYMBOL_CONTEXT_EXTRACTOR_VERSION
            and types.get("dirty_reason") == "deferred_type_refs"
            and types.get("target_version") == self.FUNCTION_TYPE_REF_EXTRACTOR_VERSION
        )

    @staticmethod
    def _record_derived_failure(
        db: Any,
        extractor: Optional[Union[ClangExtractor, ClangExtractorPool]],
        index_name: str,
        target_version: str,
        exc: Exception,
    ) -> None:
        logger.error("Derived index rebuild failed index=%s: %s", index_name, exc)
        discard_staging = getattr(db, "discard_derived_index_staging", None)
        if callable(discard_staging):
            try:
                discard_staging(index_name)
            except Exception as discard_exc:
                logger.error(
                    "Failed to discard derived staging index=%s: %s",
                    index_name,
                    discard_exc,
                )
        try:
            stats_getter = getattr(extractor, "get_last_derived_stats", None)
            last_stats = stats_getter(index_name) if callable(stats_getter) else {}
            db.fail_derived_index_rebuild(
                index_name,
                target_version,
                exc,
                last_stats,
            )
        except Exception as state_exc:
            logger.error(
                "Failed to persist derived index failure index=%s: %s",
                index_name,
                state_exc,
            )

    def _is_path_allowed(self, p: Path) -> bool:
        """Check if a path passes include/exclude filters."""
        import os

        def is_subpath(child: Path, parent: Path) -> bool:
            try:
                # Use absolute() instead of resolve() to avoid symlink physical path jumping out of bounds
                c_str = str(child.absolute())
                p_str = str(parent.absolute())

                # Case-insensitive ONLY on Windows
                if os.name == "nt":
                    c_str = c_str.lower()
                    p_str = p_str.lower()

                sep = os.sep
                if not p_str.endswith(sep):
                    p_str += sep
                return c_str.startswith(p_str) or c_str == p_str.rstrip(sep)
            except Exception:
                return False

        if self._exclude_paths:
            for ex in self._exclude_paths:
                if is_subpath(p, ex):
                    return False

        if self._include_paths:
            in_include = False
            for inc in self._include_paths:
                if is_subpath(p, inc):
                    in_include = True
                    break
            if not in_include:
                return False

        return True

    def _collect_source_files(self) -> List[Path]:
        """收集源码目录下所有 C/C++ 文件。"""
        files = []
        if self._source_path is None:
            return []
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ph", ".inc", ".inl"}

        raw_bases = self._include_paths if self._include_paths else [self._source_path]
        bases_to_search: List[Path] = []
        for base in sorted(
            {Path(value).resolve() for value in raw_bases}, key=lambda p: len(p.parts)
        ):
            covered = False
            for parent in bases_to_search:
                try:
                    base.relative_to(parent)
                    covered = True
                    break
                except ValueError:
                    continue
            if not covered:
                bases_to_search.append(base)

        for base in bases_to_search:
            try:
                for file_path in base.rglob("*"):
                    if file_path.suffix.lower() not in extensions:
                        continue
                    if self._is_path_allowed(file_path):
                        files.append(file_path.resolve())
            except (OSError, PermissionError) as exc:
                logger.debug("Skipping unreadable source subtree %s: %s", base, exc)

        # Remove duplicates
        return sorted(list(set(files)))

    def close(self) -> None:
        self._stop_type_ref_scheduler()
        if self._extractor:
            self._extractor.stop()
            self._extractor = None
        if self._db:
            self._db.close()
            self._db = None
        self._status = "idle"

    def status(self) -> str:
        return self._status

    # ── 索引构建 ──

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        """从 KnowledgeDB 构建函数索引。"""
        if not self._db:
            return {}
        return self._db.get_all_functions()

    # ── 查询方法 ──

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return None
        func = self._db.get_function(name)
        if not func:
            return None
        return {
            "name": func["name"],
            "filename": func["file_path"],
            "lineNumber": func["start_line"],
            "lineNumberEnd": func["end_line"],
            "signature": func.get("signature", f"{name}(...)"),
            "is_static": bool(func.get("is_static")),
        }

    def get_macro_definitions(self, name: str, limit: int = 20) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_macro_definitions(name, limit=limit)

    def get_macro_definitions_batch(self, names: List[str]) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_macro_definitions_batch(names)

    def get_global_definitions_batch(self, names: List[str]) -> List[Dict[str, Any]]:
        return self._db.get_global_definitions_batch(names) if self._db else []

    def get_build_contexts(self, file_path: str = "") -> List[Dict[str, Any]]:
        return self._db.get_build_contexts(file_path) if self._db else []

    def get_function_program_facts(
        self, func_name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        if not self._db:
            return {"complete": False, "events": [], "accesses": []}
        import json
        from .build_context import program_facts_result

        if build_context_id:
            # An explicit identity may name a variant where the function does
            # not exist. Report missing evidence, never borrow another variant.
            selected_context = self._db.get_build_context(build_context_id)
            if selected_context is None:
                return {
                    "complete": False,
                    "events": [],
                    "accesses": [],
                    "functions": [],
                    "reason": "build_context_not_found",
                    "build_context_id": build_context_id,
                }
            values = self._db.get_compilation_facts(
                build_context_id,
                symbol=func_name,
                file_path=file_path,
                kinds=("program_function", "program_access"),
            )
            return program_facts_result(values, context=selected_context)
        contexts = self._db.get_function_build_contexts(func_name, file_path)
        by_id = {context["build_context_id"]: context for context in contexts}
        sources = {context["source"] for context in contexts}
        if file_path:
            sources.add(file_path)
        for source in sources:
            for context in self._db.get_build_contexts(source):
                by_id[context["build_context_id"]] = context
        if len(by_id) > 1:
            return {
                "complete": False,
                "events": [],
                "accesses": [],
                "functions": [],
                "reason": "ambiguous_build_context",
                "build_contexts": list(by_id.values()),
            }
        if by_id:
            context = next(iter(by_id.values()))
            values = self._db.get_compilation_facts(
                context["build_context_id"],
                symbol=func_name,
                file_path=file_path,
                kinds=("program_function", "program_access"),
            )
            return program_facts_result(values, context=context)

        selector = (
            "json_extract(data, '$.owner.usr')=?" if func_name.startswith("c:") else "function=?"
        )
        query = "SELECT data FROM function_program_facts WHERE " + selector
        args: list[Any] = [func_name]
        if file_path:
            query += " AND file_path=?"
            args.append(file_path)
        values = [json.loads(row[0]) for row in self._db._conn.execute(query, args)]
        return program_facts_result(values)

    def get_function_symbol_context(
        self,
        func_name: str,
        file_path: str = "",
    ) -> Dict[str, List[Dict[str, Any]]]:
        if not self._db:
            return {"referenced_globals": [], "referenced_macros": []}
        return self._db.get_function_symbol_context(func_name, file_path)

    def get_function_type_context(
        self,
        func_name: str,
        file_path: str = "",
        start_line: int = 0,
    ) -> Dict[str, Any]:
        if not self._db:
            return {"referenced_types": []}
        scheduler = getattr(self, "_type_ref_scheduler", None)
        if (
            scheduler is None
            and self._frontend == "auto"
            and self._db.get_metadata("clang_type_refs_generation")
        ):
            from .clang_type_scheduler import acquire_scheduler

            scheduler = self._type_ref_scheduler = acquire_scheduler(self)
        if scheduler is not None:
            if scheduler.generation != self._db.get_metadata("clang_type_refs_generation"):
                from .clang_type_scheduler import acquire_scheduler

                self._stop_type_ref_scheduler()
                scheduler = self._type_ref_scheduler = acquire_scheduler(self)
            from .clang_type_state import function_record, read_current, TypeContextUnavailable

            record = function_record(self._db, func_name, file_path, start_line)
            if record is None:
                raise TypeContextUnavailable("function_identity_ambiguous_or_missing")
            if record.get("context") != "native":
                logger.debug(
                    "[function-type-refs] consumer_wait function=%s file=%s line=%s",
                    func_name,
                    file_path,
                    start_line,
                )
                scheduler.ensure(record)
                result = read_current(
                    self._db, func_name, file_path, start_line, record["generation"]
                )
                if result is None:
                    raise TypeContextUnavailable("base_generation_changed")
                return result
        return self._db.get_function_type_context(func_name, file_path, start_line)

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callees(name, limit=limit)

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callers(func_name, limit=limit, callee_file=callee_file)

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callees(func_name, limit=limit)

    def get_function_info_callees(
        self,
        func_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_all_callees(func_name, caller_file=file_path)

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return None
        return self._db.get_type_info(type_name)

    def find_type_infos(
        self,
        type_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.find_type_infos(type_name, file_path=file_path)

    def get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        """Clang 后端暂不支持数据流分析（需 SVF 集成）。"""
        logger.debug("Data flow analysis not available in Clang backend (requires SVF)")
        return []

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """通过 KnowledgeDB call_edges 中 call_type='indirect' 查找函数指针。"""
        if not self._db:
            return []
        rows = self._db._conn.execute(
            "SELECT DISTINCT caller_name, caller_file, call_line "
            "FROM call_edges WHERE callee_name = ? AND call_type = 'indirect' LIMIT 20",
            (func_name,),
        ).fetchall()
        return [
            {"caller": r["caller_name"], "file": r["caller_file"], "line": r["call_line"]}
            for r in rows
        ]

    def get_header_declared_functions(
        self, header_files: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_header_functions(header_files, source_root=self._source_path)
