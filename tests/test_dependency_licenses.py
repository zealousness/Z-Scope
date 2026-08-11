from __future__ import annotations

import json
from email.message import Message
from pathlib import Path

import pytest

from scripts import check_dependency_licenses as licenses


def test_parse_locked_requirements_normalizes_names(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text(
        "Foo_Bar==1.2.3 \\\n+    --hash=sha256:abc\nother.package==4.5.6 \\\n+    --hash=sha256:def\n",
        encoding="utf-8",
    )

    assert licenses.parse_locked_requirements(lock) == {
        "foo-bar": "1.2.3",
        "other-package": "4.5.6",
    }


def test_load_policy_rejects_wrong_schema(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"schema_version": 2, "packages": {"foo": "MIT"}}), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="schema_version"):
        licenses.load_policy(policy)


def test_installed_license_uses_classifier_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    package_metadata = Message()
    package_metadata["Classifier"] = "License :: OSI Approved :: Apache Software License"
    monkeypatch.setattr(licenses.metadata, "metadata", lambda _: package_metadata)

    assert licenses.installed_license("example") == "Apache-2.0"


def test_check_policy_reports_license_and_inventory_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(licenses.metadata, "version", lambda _: "1.0")
    monkeypatch.setattr(licenses, "installed_license", lambda _: "MIT")

    errors = licenses.check_policy(
        {"present": "1.0", "missing-policy": "1.0"},
        {"present": "Apache-2.0", "stale-policy": "MIT"},
    )

    assert "missing-policy: missing from license policy" in errors
    assert "stale-policy: policy entry is not present in the release lock" in errors
    assert any("observed license 'MIT' is not approved" in error for error in errors)
