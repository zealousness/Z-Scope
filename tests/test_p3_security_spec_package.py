import zipfile
from pathlib import Path

from scripts.check_p3_security_spec_package import (
    PREFIX,
    REQUIRED_QUALIFICATION,
    REQUIRED_MODULES,
    REQUIRED_SCHEMAS,
    wheel_errors,
)


def _wheel(path: Path, *, omit_schema: bool = False, forbidden_import: str = "") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in REQUIRED_MODULES:
            source = ""
            if forbidden_import and name.endswith("compiler.py"):
                source = f"import {forbidden_import}\n"
            archive.writestr(name, source)
        for index, name in enumerate(sorted(REQUIRED_SCHEMAS)):
            if omit_schema and index == 0:
                continue
            archive.writestr(PREFIX + "schemas/" + name, "{}")
        archive.writestr(REQUIRED_QUALIFICATION, "{}")


def test_security_spec_wheel_gate_accepts_complete_package(tmp_path: Path) -> None:
    path = tmp_path / "complete.whl"
    _wheel(path)
    assert wheel_errors(path) == []


def test_security_spec_wheel_gate_rejects_missing_schema(tmp_path: Path) -> None:
    path = tmp_path / "missing.whl"
    _wheel(path, omit_schema=True)
    assert any("missing SecuritySpec schema" in value for value in wheel_errors(path))


def test_security_spec_wheel_gate_rejects_authority_import(tmp_path: Path) -> None:
    path = tmp_path / "forbidden.whl"
    _wheel(path, forbidden_import="zscope.core.validation.runner")
    assert any("forbidden authority dependency" in value for value in wheel_errors(path))
