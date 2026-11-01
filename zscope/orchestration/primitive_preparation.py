"""The CLI and Web entry point for native inventory and primitive discovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config.project_semantics import canonical_digest
from ..config.semantics_workflow import project_activity, discovery_snapshot


class PreparationCancelled(Exception):
    pass


def run_preparation(
    config: Any, *, mode: str = "discovery", progress: Any = None
) -> dict[str, Any]:
    from ..retrieval.code_index import CodeIndex
    from ..config.project_semantics import ProjectSemanticsStore
    from .primitive_discovery import discover_project_primitives, _stream_function_work

    if config.project.language != "c_cpp" or mode not in {"inventory", "discovery"}:
        raise ValueError("项目原语仅适用于 C/C++；任务类型必须为 inventory 或 discovery。")

    def emit(stage: str, **details: Any) -> None:
        if progress:
            progress(stage, details)

    root = Path(config.project.project_root)
    with project_activity(root):
        emit("preparing_index")
        index = CodeIndex(
            root,
            config.project.compile_commands_path,
            source_root=root,
            indexing_config=config.indexing,
            include_paths=config.project.include_paths,
            exclude_paths=config.project.exclude_paths,
            wait_for_cpg=True,
            defer_svf=True,
            svf_parallel_workers=config.concurrency.svf_workers or config.concurrency.index_workers,
        )
        client = None
        try:
            if mode == "inventory":
                emit("native_inventory")
                scopes, gaps, work, _ = _stream_function_work(index, root)
                if gaps:
                    raise ValueError("native 接口目录不完整：" + "; ".join(gaps[:24]))
                document = ProjectSemanticsStore(config.project.semantics_file).read(
                    allow_unbound_primitive_proposals=True
                )
                snapshot = discovery_snapshot(config, index, document)
                rows = []
                for functions in work.values():
                    for scope, impl, facts, name, signature in functions:
                        source = Path(scope.source).resolve()
                        if not source.is_relative_to(root):
                            continue
                        rows.append(
                            {
                                "id": canonical_digest([scope.build_context_id, scope.usr]),
                                "name": name,
                                "signature": signature,
                                "usr": scope.usr,
                                "file": source.relative_to(root).as_posix(),
                                "build_context_id": scope.build_context_id,
                                "target_id": config.project.target_id,
                                "line": impl.get("start_line", impl.get("line", 1)),
                                "parameter_count": len(
                                    (facts.get("functions") or [{}])[0].get("parameters") or []
                                ),
                            }
                        )
                emit("merging", processed=len(scopes))
                return {"mode": mode, "snapshot": snapshot, "symbols": rows}
            from ..framework.llm_client import LLMClient
            from ..framework.llm_usage import ensure_scan_token_usage_ledger

            ref = config.scan.llm_profiles.modeling
            profile = config.llms[ref]
            # A broken model connection must not discard deterministic native
            # candidates. The core records client_unavailable and keeps pending.
            try:
                client = LLMClient(
                    api_key=profile.api_key,
                    base_url=profile.base_urls or profile.base_url,
                    models=profile.models,
                    timeout=profile.timeout,
                    max_retries=profile.max_retries,
                    retry_until_available=False,
                    max_tokens=profile.max_tokens,
                    context_window=profile.context_window,
                    model_context_windows=profile.model_context_windows,
                    base_url_rate_limit_per_minute=profile.base_url_rate_limit_per_minute,
                    base_url_max_concurrent_requests=profile.base_url_max_concurrent_requests,
                    global_max_concurrent_requests=config.concurrency.llm_max_inflight,
                    supports_structured_output=profile.supports_structured_output,
                    token_usage_ledger=ensure_scan_token_usage_ledger(config),
                    llm_ref=ref,
                )
            except (ValueError, OSError) as exc:
                emit("model_unavailable", error=str(exc))
            return discover_project_primitives(config, index, llm_client=client, progress=progress)
        finally:
            if client is not None:
                client.close()
            index.close()
