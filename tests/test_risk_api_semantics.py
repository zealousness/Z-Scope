"""Tests for the extended 13-role user-defined risk interface semantics."""

from __future__ import annotations

import pytest

from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.inference import (
    add_api_for_config_kind,
    classify_snapshot_role,
)
from zscope.semantics.models import (
    CATEGORY_BY_ATTR,
    LocalPatternSemantics,
    attr_for_category,
    classify_api_name,
)


EXTENDED_ATTRS = (
    "io_acquirers",
    "io_releasers",
    "send_sinks",
    "recv_sources",
    "format_sinks",
    "callback_registrars",
)


def test_local_pattern_semantics_has_extended_role_buckets() -> None:
    semantics = LocalPatternSemantics()
    for attr in EXTENDED_ATTRS:
        bucket = getattr(semantics, attr)
        assert bucket == {}, f"unexpected initial content in {attr}"
        assert attr in CATEGORY_BY_ATTR or attr.endswith("s")


def test_add_api_routes_extended_categories() -> None:
    semantics = LocalPatternSemantics()
    cases = {
        "io_acquire": "io_acquirers",
        "io_release": "io_releasers",
        "send_sink": "send_sinks",
        "recv_source": "recv_sources",
        "format_sink": "format_sinks",
        "callback_register": "callback_registrars",
    }
    for category, attr in cases.items():
        semantics.add_api(category, f"proj_{category}_api", "user_config")
        bucket = getattr(semantics, attr)
        assert f"proj_{category}_api" in bucket
        assert bucket[f"proj_{category}_api"] == ["user_config"]


def test_add_api_records_sources_per_name() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("allocator", "proj_alloc", "builtin_defaults")
    semantics.add_api("allocator", "proj_alloc", "user_config")
    assert semantics.allocators["proj_alloc"] == ["builtin_defaults", "user_config"]
    assert "proj_alloc" in semantics.names_from_nondefault_sources("allocators")


def test_names_from_nondefault_sources_protects_builtin_defaults() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("allocator", "malloc", "builtin_defaults")
    semantics.add_api("allocator", "proj_alloc", "builtin_defaults")
    semantics.add_api("allocator", "proj_alloc", "user_config")
    semantics.add_api("allocator", "other_alloc", "name_heuristic")
    names = semantics.names_from_nondefault_sources("allocators")
    assert "malloc" not in names
    assert "proj_alloc" in names
    assert "other_alloc" in names


@pytest.mark.parametrize(
    "name,expected",
    [
        ("file_open_wrap", "io_acquire"),
        ("wrap_socket_open", "io_acquire"),
        ("shm_socket_create", ""),  # socket is not the last token: conservative
        ("file_close_wrap", "io_release"),
        ("conn_disconnect", "io_release"),
        ("close_report", "io_release"),  # substring heuristic; user config can correct
        ("net_send_wrap", "send_sink"),
        ("event_emit", "send_sink"),
        ("emit_event", ""),  # emit only matches as the last token
        ("net_recv_wrap", "recv_source"),
        ("frame_read", "recv_source"),
        ("read_config", ""),  # read only matches as the last token
        ("audit_log", "format_sink"),
        ("write_syslog", "format_sink"),
        ("cb_register", "callback_register"),
        ("worker_subscribe", "callback_register"),
        ("unregister_cb", ""),
    ],
)
def test_classify_api_name_extended_categories(name: str, expected: str) -> None:
    assert classify_api_name(name) == expected


def test_classify_api_name_keeps_uppercase_macros_unclassified() -> None:
    assert classify_api_name("NET_SEND_WRAP") == ""
    assert classify_api_name("AUDIT_LOG") == ""


def test_defaults_cover_extended_roles() -> None:
    semantics = default_local_pattern_semantics()
    assert {"open", "fopen", "creat", "socket", "accept"} <= set(semantics.io_acquirers)
    assert {"close", "fclose", "closesocket", "munmap"} <= set(semantics.io_releasers)
    assert {"send", "write", "sendto", "sendmsg"} <= set(semantics.send_sinks)
    assert {"recv", "read", "recvfrom"} <= set(semantics.recv_sources)
    assert {"printf", "fprintf", "syslog", "vprintf"} <= set(semantics.format_sinks)
    assert "register_callback" in semantics.callback_registrars
    # Builtin memory/lock defaults must stay untouched by the extension.
    assert "malloc" in semantics.allocators
    assert "free" in semantics.deallocators
    assert "pthread_mutex_lock" in semantics.lock_apis


def test_extended_defaults_are_builtin_sourced() -> None:
    semantics = default_local_pattern_semantics()
    # Every extended default comes from builtin_defaults, so checkers that
    # consume names_from_nondefault_sources keep their builtin behavior.
    for attr in EXTENDED_ATTRS:
        assert semantics.names_from_nondefault_sources(attr) == set()


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("allocator", "allocators"),
        ("io_acquire", "io_acquirers"),
        ("io_release", "io_releasers"),
        ("send_sink", "send_sinks"),
        ("recv_source", "recv_sources"),
        ("format_sink", "format_sinks"),
        ("callback_register", "callback_registrars"),
        ("lock", "lock_apis"),
        ("unlock", "unlock_apis"),
    ],
)
def test_add_api_for_config_kind_supports_extended_kinds(kind: str, expected: str) -> None:
    semantics = LocalPatternSemantics()
    assert add_api_for_config_kind(semantics, "proj_api", kind, "user_config") is True
    bucket = getattr(semantics, expected)
    assert bucket.get("proj_api") == ["user_config"]


def test_add_api_for_config_kind_rejects_unknown_kind() -> None:
    semantics = LocalPatternSemantics()
    assert add_api_for_config_kind(semantics, "magic_kind", "proj_api", "user_config") is False


def test_classify_snapshot_role_from_structured_effects() -> None:
    allocator = {
        "return_values": {"ownership": "caller_owned"},
        "effects": [
            {"category": "memory", "details": {"allocation_kind": "malloc"}},
            {"category": "ownership", "details": {}},
        ],
    }
    assert classify_snapshot_role(allocator) == "allocator"
    assert classify_snapshot_role(
        {"effects": [{"category": "lock", "details": {"operation_kind": "acquire"}}]}
    ) == "lock"
    assert classify_snapshot_role(
        {"effects": [{"category": "lock", "details": {"operation_kind": "release"}}]}
    ) == "unlock"
    assert classify_snapshot_role(
        {"effects": [{"category": "io", "details": {"operation_kind": "log"}}]}
    ) == "format_sink"


def test_classify_snapshot_role_prefers_explicit_role() -> None:
    snapshot = {
        "role": "recv_source",
        "effects": [{"category": "memory", "details": {}}],
    }
    assert classify_snapshot_role(snapshot) == "recv_source"
    # Unknown explicit roles fall through to the deterministic rules.
    assert classify_snapshot_role({"role": "helper"}) == ""
    assert classify_snapshot_role({}) == ""


def test_semantics_merge_keeps_extended_buckets() -> None:
    left = LocalPatternSemantics()
    right = LocalPatternSemantics()
    left.add_api("send_sink", "net_send_wrap", "user_config")
    right.add_api("send_sink", "net_send_wrap", "semantic_snapshot")
    right.add_api("recv_source", "net_recv_wrap", "user_config")
    left.merge(right)
    assert left.send_sinks["net_send_wrap"] == ["user_config", "semantic_snapshot"]
    assert left.recv_sources["net_recv_wrap"] == ["user_config"]
