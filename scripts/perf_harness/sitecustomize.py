"""Run-local Z-Scope performance instrumentation.

This module is loaded by Python's normal ``sitecustomize`` hook only when the
profile runner prepends ``scripts/perf_harness`` to ``PYTHONPATH``. It is inert
unless ``Z_SCOPE_PERF_TIMELINE`` is set.
"""

from __future__ import annotations

import functools
import importlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional


_TIMELINE = os.environ.get("Z_SCOPE_PERF_TIMELINE", "").strip()
_RUN_ID = os.environ.get("Z_SCOPE_PERF_RUN_ID", "").strip()
_LOCK = threading.Lock()


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value[:40]]
    if isinstance(value, dict):
        return {
            str(key): _json_safe(val)
            for key, val in list(value.items())[:80]
            if str(key).lower() not in {"api_key", "authorization", "prompt", "content"}
        }
    return str(value)


def _write_event(event: Dict[str, Any]) -> None:
    if not _TIMELINE:
        return
    event.setdefault("ts", time.time())
    event.setdefault("run_id", _RUN_ID)
    event.setdefault("thread", threading.current_thread().name)
    line = json.dumps(event, ensure_ascii=False, sort_keys=True)
    with _LOCK:
        with open(_TIMELINE, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _entry_name(value: Any) -> str:
    return str(getattr(value, "function_name", "") or value or "")


def _config_entry(obj: Any) -> str:
    config = getattr(obj, "config", None)
    project = getattr(config, "project", None)
    return str(getattr(project, "entry_function", "") or "")


def _summarize_result(result: Any) -> Dict[str, Any]:
    details: Dict[str, Any] = {}
    if isinstance(result, dict):
        if "functions" in result and isinstance(result.get("functions"), list):
            details["function_count"] = len(result["functions"])
        if "issues" in result and isinstance(result.get("issues"), list):
            details["issue_count"] = len(result["issues"])
        if "summary" in result and isinstance(result.get("summary"), dict):
            summary = result["summary"]
            for key in (
                "functions_analyzed",
                "total_issues",
                "batch_wall_seconds",
                "total_cumulative_total_tokens",
            ):
                if key in summary:
                    details[key] = summary[key]
    elif isinstance(result, list):
        details["result_count"] = len(result)
    return details


def _llm_details(args: tuple[Any, ...], kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    messages = kwargs.get("messages")
    if messages is None and args:
        messages = args[0]
    details: Dict[str, Any] = {
        "message_count": len(messages) if isinstance(messages, list) else 0,
        "trace_label": str(kwargs.get("trace_label") or "")[:160],
        "trace_iteration": kwargs.get("trace_iteration"),
    }
    if isinstance(result, dict):
        usage = result.get("usage")
        if isinstance(usage, dict):
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                if key in usage:
                    details[key] = usage[key]
        choices = result.get("choices")
        if isinstance(choices, list):
            details["choice_count"] = len(choices)
    return details


def _tool_details(args: tuple[Any, ...], kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    tool_name = args[0] if args else kwargs.get("name")
    details = {"tool_name": str(tool_name or "")}
    if isinstance(result, dict):
        if "success" in result:
            details["success"] = bool(result.get("success"))
        if result.get("error"):
            details["error"] = str(result.get("error"))[:240]
    return details


def _agent_tool_details(args: tuple[Any, ...], kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    details = _tool_details(args, kwargs, result)
    tool_args = args[1] if len(args) > 1 else kwargs.get("args")
    if isinstance(tool_args, dict):
        for key in ("func_name", "file_path", "type_name", "start_line", "end_line", "limit"):
            if key in tool_args:
                details[key] = tool_args[key]
    return details


def _entry_details(args: tuple[Any, ...], _kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    entry = args[0] if args else None
    details = {"entry": _entry_name(entry)}
    details.update(_summarize_result(result))
    return details


def _entries_details(args: tuple[Any, ...], _kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    entries = args[0] if args else []
    details = {"entry_count": len(entries) if isinstance(entries, list) else 0}
    details.update(_summarize_result(result))
    return details


def _function_impl_details(args: tuple[Any, ...], kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    details = {
        "function_name": str(args[0] if args else kwargs.get("func_name") or ""),
        "include_context": bool(kwargs.get("include_context", True)),
        "file_path": str(kwargs.get("file_path") or "")[:240],
    }
    if isinstance(result, dict):
        details["found"] = True
        details["line_count"] = len(str(result.get("code") or "").splitlines())
    else:
        details["found"] = False
    return details


def _file_snippet_details(args: tuple[Any, ...], kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    details = {
        "file_path": str(args[0] if args else kwargs.get("file_path") or "")[:240],
        "start_line": args[1] if len(args) > 1 else kwargs.get("start_line"),
        "end_line": args[2] if len(args) > 2 else kwargs.get("end_line"),
        "found": result is not None,
    }
    if isinstance(result, dict):
        code = result.get("code")
        if isinstance(code, str):
            details["line_count"] = len(code.splitlines())
    return details


def _callers_details(args: tuple[Any, ...], kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    details = {
        "function_name": str(args[0] if args else kwargs.get("func_name") or ""),
        "limit": args[1] if len(args) > 1 else kwargs.get("limit"),
    }
    if isinstance(result, list):
        details["caller_count"] = len(result)
    return details


def _type_info_details(args: tuple[Any, ...], kwargs: Dict[str, Any], result: Any) -> Dict[str, Any]:
    return {
        "type_name": str(args[0] if args else kwargs.get("type_name") or ""),
        "found": result is not None,
    }


def _wrap(
    module_name: str,
    class_name: str,
    method_name: str,
    phase: str,
    detail_fn: Optional[Callable[[tuple[Any, ...], Dict[str, Any], Any], Dict[str, Any]]] = None,
) -> None:
    try:
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        original = getattr(cls, method_name)
    except Exception as exc:
        _write_event(
            {
                "event": "instrumentation_error",
                "target": f"{module_name}.{class_name}.{method_name}",
                "error": str(exc)[:240],
            }
        )
        return
    if getattr(original, "__zscope_perf_wrapped__", False):
        return

    @functools.wraps(original)
    def wrapped(self: Any, *args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        error = ""
        result: Any = None
        try:
            result = original(self, *args, **kwargs)
            return result
        except Exception as exc:
            error = type(exc).__name__
            raise
        finally:
            details: Dict[str, Any] = {}
            if detail_fn:
                try:
                    details = detail_fn(args, kwargs, result)
                except Exception as detail_exc:
                    details = {"detail_error": str(detail_exc)[:240]}
            details = _json_safe(details)
            _write_event(
                {
                    "event": "timing",
                    "phase": phase,
                    "target": f"{module_name}.{class_name}.{method_name}",
                    "entry": details.get("entry") or _config_entry(self),
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "error": error,
                    "details": details,
                }
            )

    wrapped.__zscope_perf_wrapped__ = True
    setattr(cls, method_name, wrapped)


def _install() -> None:
    if not _TIMELINE:
        return
    Path(_TIMELINE).parent.mkdir(parents=True, exist_ok=True)
    _write_event({"event": "instrumentation_started"})
    _wrap("zscope.retrieval.code_index", "CodeIndex", "get_function_impl", "code_index.get_function_impl", _function_impl_details)
    _wrap("zscope.retrieval.code_index", "CodeIndex", "get_file_snippet", "code_index.get_file_snippet", _file_snippet_details)
    _wrap("zscope.retrieval.code_index", "CodeIndex", "get_callers", "code_index.get_callers", _callers_details)
    _wrap("zscope.retrieval.code_index", "CodeIndex", "get_type_info", "code_index.get_type_info", _type_info_details)
    _wrap("zscope.retrieval.code_index", "CodeIndex", "list_functions", "code_index.list_functions")
    _wrap("zscope.retrieval.code_index", "CodeIndex", "run_svf", "code_index.run_svf")
    _wrap("zscope.orchestration.entry_discovery", "EntryDiscovery", "discover", "entry_discovery.discover", lambda _a, _k, r: {"candidate_count": len(getattr(r, "candidates", []) or []), "summary": getattr(r, "summary", {})})
    _wrap("zscope.orchestration.entry_discovery", "EntryDiscovery", "_discover_header_api", "entry_discovery.header_api")
    _wrap("zscope.orchestration.entry_discovery", "EntryDiscovery", "_discover_body_entries", "entry_discovery.body_entries")
    _wrap("zscope.retrieval.clang_backend", "ClangBackend", "_run_full_extraction", "clang.full_extraction")
    _wrap("zscope.retrieval.svf_analyzer", "SvfAnalyzer", "run", "svf.run")
    _wrap("zscope.retrieval.svf_analyzer", "SvfAnalyzer", "_build_bitcode", "svf.build_bitcode")
    _wrap("zscope.retrieval.svf_analyzer", "SvfAnalyzer", "_run_split_svf", "svf.run_split")
    _wrap("zscope.orchestration.parallel_analyzer", "ParallelAnalyzer", "_prepare_shared_semantics", "batch.shared_semantics")
    _wrap("zscope.orchestration.parallel_analyzer", "ParallelAnalyzer", "_create_config_for_entry", "batch.create_entry_config", _entry_details)
    _wrap("zscope.orchestration.parallel_analyzer", "ParallelAnalyzer", "_analyze_single_entry", "batch.entry_analysis", _entry_details)
    _wrap("zscope.orchestration.parallel_analyzer", "ParallelAnalyzer", "analyze_function_entries", "batch.analyze_entries", _entries_details)
    _wrap("zscope.orchestration.parallel_analyzer", "ParallelAnalyzer", "generate_combined_report", "batch.generate_report", lambda _a, _k, r: _summarize_result(r))
    _wrap("zscope.core.analysis.analyzer", "Analyzer", "_step_model_entry", "entry.model_entry")
    _wrap("zscope.core.analysis.analyzer", "Analyzer", "_step_vulnerability_mining", "entry.vulnerability_mining")
    _wrap("zscope.core.analysis.analyzer", "Analyzer", "_step_validate_findings", "entry.validate_findings")
    _wrap("zscope.core.analysis.analyzer", "Analyzer", "_deduplicate_report_issues", "entry.report_dedup", lambda _a, _k, r: {"issue_count": len(r) if isinstance(r, list) else 0})
    _wrap("zscope.core.analysis.analyzer", "Analyzer", "_deduplicate_report_clusters_with_llm", "entry.llm_dedup", lambda _a, _k, r: {"issue_count": len(r[0]) if isinstance(r, tuple) and r else 0, "summary": r[1] if isinstance(r, tuple) and len(r) > 1 else {}})
    _wrap("zscope.framework.llm_client", "LLMClient", "chat_completion", "llm.chat_completion", _llm_details)
    _wrap("zscope.framework.llm_client", "LLMClient", "run_conversation_with_tools", "llm.tool_loop")
    _wrap("zscope.agents.base", "ToolCallingAgent", "_tool_executor", "agent.tool_execute", _agent_tool_details)
    _wrap("zscope.tools.runtime", "ToolsRuntime", "execute_tool", "tool.execute", _tool_details)


_install()
