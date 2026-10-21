"""Tests that user_config rows of the extended kinds compile into the overlay."""

from __future__ import annotations

from zscope.core.candidates.evidence import SemanticOverlayCompiler, overlay_summary


class ExtendedKindsUserConfig:
    def list_external_functions(self):
        return [
            {
                "func_name": "file_open_wrap",
                "kind": "io_acquire",
                "symbol_type": "function",
                "description": "resource_output=return",
            },
            {
                "func_name": "file_close_wrap",
                "kind": "io_release",
                "symbol_type": "function",
                "description": "resource_input=arg1",
            },
            {
                "func_name": "net_send_wrap",
                "kind": "send_sink",
                "symbol_type": "function",
                "description": "resource_input=arg2; size_arg=arg3",
            },
            {
                "func_name": "net_recv_wrap",
                "kind": "recv_source",
                "symbol_type": "function",
                "description": "resource_output=arg2",
            },
            {
                "func_name": "audit_log",
                "kind": "format_sink",
                "symbol_type": "function",
                "description": "format_arg=arg1",
            },
            {
                "func_name": "cb_register",
                "kind": "callback_register",
                "symbol_type": "function",
                "description": "callback_arg=arg1",
            },
            {
                "func_name": "ZIP_SEND",
                "kind": "send_sink",
                "symbol_type": "macro",
                "description": "resource_input=arg1",
            },
        ]

    def list_paired_functions(self):
        return [
            {
                "category": "resource",
                "acquire_func": "shm_open_wrap",
                "release_func": "shm_close_wrap",
                "description": "file handle lifecycle (io)",
            }
        ]

    def list_dispatchers(self):
        return []

    def list_module_lifecycle(self):
        return []

    def get_pointer_targets(self):
        return []

    def list_function_intents(self):
        return []


def test_overlay_compiles_extended_kind_models() -> None:
    overlay = SemanticOverlayCompiler(ExtendedKindsUserConfig()).compile()
    by_name = {model["name"]: model for model in overlay["resource_models"]}

    expected_kinds = {
        "file_open_wrap": "io_acquire",
        "file_close_wrap": "io_release",
        "net_send_wrap": "send_sink",
        "net_recv_wrap": "recv_source",
        "audit_log": "format_sink",
        "cb_register": "callback_register",
    }
    for name, kind in expected_kinds.items():
        assert name in by_name, f"{name} missing from resource_models"
        assert by_name[name]["kind"] == kind


def test_overlay_summary_includes_extended_names() -> None:
    overlay = SemanticOverlayCompiler(ExtendedKindsUserConfig()).compile()
    summary = overlay_summary(overlay)
    for name in (
        "file_open_wrap",
        "net_send_wrap",
        "net_recv_wrap",
        "audit_log",
        "cb_register",
    ):
        assert name in summary["resource_names"]


def test_overlay_paired_io_functions_become_resource_models() -> None:
    overlay = SemanticOverlayCompiler(ExtendedKindsUserConfig()).compile()
    by_name = {model["name"]: model for model in overlay["resource_models"]}
    assert by_name["shm_open_wrap"]["kind"] in {"io_acquire", "resource_acquire"}
    assert by_name["shm_close_wrap"]["kind"] in {"io_release", "resource_release"}


def test_user_config_names_are_nondefault_sources_in_semantics() -> None:
    from zscope.semantics.inference import add_api_for_config_kind
    from zscope.semantics.models import LocalPatternSemantics

    semantics = LocalPatternSemantics()
    for row in ExtendedKindsUserConfig().list_external_functions():
        assert add_api_for_config_kind(
            semantics, row["func_name"], row["kind"], "user_config"
        )
    for bucket_attr, expected_names in (
        ("io_acquirers", {"file_open_wrap"}),
        ("io_releasers", {"file_close_wrap"}),
        ("send_sinks", {"net_send_wrap", "ZIP_SEND"}),
        ("recv_sources", {"net_recv_wrap"}),
        ("format_sinks", {"audit_log"}),
        ("callback_registrars", {"cb_register"}),
    ):
        names = semantics.names_from_nondefault_sources(bucket_attr)
        assert names == expected_names, f"{bucket_attr}: {names}"
