"""Tests for Clang-AST/CFG candidate generation driven by custom API semantics."""

from __future__ import annotations

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import LocalPatternSemantics, RegexCandidateGenerator


def _extended_semantics() -> LocalPatternSemantics:
    semantics = LocalPatternSemantics()
    semantics.add_api("io_acquire", "file_open_wrap", "user_config")
    semantics.add_api("io_release", "file_close_wrap", "user_config")
    semantics.add_api("send_sink", "net_send_wrap", "user_config")
    semantics.add_api("recv_source", "net_recv_wrap", "user_config")
    semantics.add_api("format_sink", "audit_log", "user_config")
    semantics.add_api("callback_register", "cb_register", "user_config")
    semantics.add_api("allocator", "proj_alloc", "user_config")
    return semantics


def test_compile_api_models_consumes_extended_semantics() -> None:
    generator = ClangAstCfgCandidateGenerator(_extended_semantics())

    assert "file_open_wrap" in generator._io_acquire_names
    assert "file_open_wrap" in generator._user_io_acquire_names
    assert "file_close_wrap" in generator._io_release_names
    assert "file_close_wrap" in generator._user_io_release_names
    assert "net_send_wrap" in generator._send_sink_names
    assert "net_send_wrap" in generator._user_send_sink_names
    assert "net_recv_wrap" in generator._recv_source_names
    assert "net_recv_wrap" in generator._user_recv_source_names
    assert "audit_log" in generator._format_sink_names
    assert "cb_register" in generator._callback_registrar_names


def test_builtin_base_sets_unchanged_without_user_semantics() -> None:
    generator = ClangAstCfgCandidateGenerator(LocalPatternSemantics())

    assert {"send", "write", "sendto", "sendmsg"} <= generator._send_sink_names
    assert {"recv", "read", "recvfrom"} <= generator._recv_source_names
    assert {"printf", "fprintf", "syslog", "vprintf", "vfprintf"} <= generator._format_sink_names
    assert "register_callback" not in generator._callback_registrar_names
    assert {"close", "closesocket"} <= generator._io_release_names
    assert generator._user_send_sink_names == set()
    assert generator._user_recv_source_names == set()


def test_names_pattern_bare_alternation_with_empty_fallback() -> None:
    assert ClangAstCfgCandidateGenerator._names_pattern(set()) == "__zscope_no_api_match__"
    pattern = ClangAstCfgCandidateGenerator._names_pattern({"send", "net_send_wrap"})
    assert pattern == "net_send_wrap|send"


def test_fd_open_names_exclude_state_machine_exclusions_and_accept_user_names() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("io_acquire", "shm_file_open", "user_config")
    generator = ClangAstCfgCandidateGenerator(semantics)

    open_names = generator._fd_open_names()
    assert "shm_file_open" in open_names
    assert "open" in open_names and "socket" in open_names
    for excluded in ("fopen", "popen", "fdopen", "freopen"):
        assert excluded not in open_names
    assert "malloc" not in open_names
    close_names = generator._fd_close_names()
    assert "shm_file_open" not in close_names
    assert "file_close_wrap" not in close_names


def test_overlay_rows_route_extended_kinds_into_name_sets() -> None:
    overlay = {
        "resource_models": [
            {"name": "overlay_open", "kind": "io_acquire", "description": "resource_output=return"},
            {"name": "overlay_close", "kind": "io_release", "description": "resource_input=arg1"},
            {"name": "overlay_send", "kind": "send_sink", "description": "resource_input=arg1"},
            {"name": "overlay_recv", "kind": "recv_source", "description": "resource_output=arg2"},
        ]
    }
    generator = ClangAstCfgCandidateGenerator(_extended_semantics(), semantic_overlay=overlay)

    assert "overlay_open" in generator._io_acquire_names
    assert "overlay_open" in generator._user_io_acquire_names
    assert "overlay_close" in generator._io_release_names
    assert "overlay_send" in generator._send_sink_names
    assert "overlay_recv" in generator._recv_source_names


def test_regex_generator_exposes_extended_categories() -> None:
    generator = RegexCandidateGenerator(_extended_semantics())

    assert "net_send_wrap" in generator._send_sink_names
    assert "net_recv_wrap" in generator._recv_source_names
    assert "audit_log" in generator._format_sink_names
    assert "file_open_wrap" in generator._io_acquire_names
    assert "file_close_wrap" in generator._io_release_names
    assert "cb_register" in generator._callback_registrar_names
    assert generator._user_send_sink_names == {"net_send_wrap"}
