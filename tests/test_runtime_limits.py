import sys
from types import SimpleNamespace

from zscope.common import runtime_limits


class FakeResource:
    RLIMIT_NOFILE = 7
    RLIM_INFINITY = -1

    def __init__(self, soft: int, hard: int) -> None:
        self.limits = (soft, hard)
        self.calls = []

    def getrlimit(self, resource_id: int):
        assert resource_id == self.RLIMIT_NOFILE
        return self.limits

    def setrlimit(self, resource_id: int, limits):
        assert resource_id == self.RLIMIT_NOFILE
        self.calls.append(limits)
        self.limits = limits


def test_ensure_linux_nofile_limit_raises_soft_limit(monkeypatch) -> None:
    fake_resource = FakeResource(soft=1024, hard=100000)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "resource", fake_resource)

    changed = runtime_limits.ensure_linux_nofile_limit()

    assert changed is True
    assert fake_resource.calls == [(runtime_limits.DEFAULT_LINUX_NOFILE_LIMIT, 100000)]


def test_ensure_linux_nofile_limit_caps_to_hard_limit(monkeypatch) -> None:
    fake_resource = FakeResource(soft=1024, hard=4096)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "resource", fake_resource)

    changed = runtime_limits.ensure_linux_nofile_limit()

    assert changed is True
    assert fake_resource.calls == [(4096, 4096)]


def test_ensure_linux_nofile_limit_skips_non_linux(monkeypatch) -> None:
    fake_resource = SimpleNamespace(calls=[])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "resource", fake_resource)

    changed = runtime_limits.ensure_linux_nofile_limit()

    assert changed is False
    assert fake_resource.calls == []


def test_ensure_linux_nofile_limit_keeps_unlimited_soft_limit(monkeypatch) -> None:
    fake_resource = FakeResource(
        soft=FakeResource.RLIM_INFINITY,
        hard=FakeResource.RLIM_INFINITY,
    )
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "resource", fake_resource)

    changed = runtime_limits.ensure_linux_nofile_limit()

    assert changed is False
    assert fake_resource.calls == []
