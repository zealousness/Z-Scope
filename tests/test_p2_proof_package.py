import zipfile
from pathlib import Path

from scripts.check_p2_proof_package import REQUIRED_MODULES, REQUIRED_SCHEMAS, wheel_errors


def _wheel(
    path: Path,
    *,
    omit_module: str = "",
    omit_schema: bool = False,
    forbidden_import: str = "",
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in REQUIRED_MODULES:
            if name == omit_module:
                continue
            source = ""
            if forbidden_import and name.endswith("checker.py"):
                source = f"import {forbidden_import}\n"
            archive.writestr(name, source)
        for index, name in enumerate(sorted(REQUIRED_SCHEMAS)):
            if omit_schema and index == 0:
                continue
            archive.writestr(f"zscope/core/validation/proof_kernel/schemas/{name}", "{}")


def test_proof_kernel_wheel_gate_accepts_complete_package(tmp_path: Path) -> None:
    wheel = tmp_path / "complete.whl"
    _wheel(wheel)
    assert wheel_errors(wheel) == []


def test_proof_kernel_wheel_gate_rejects_missing_schema(tmp_path: Path) -> None:
    wheel = tmp_path / "missing.whl"
    _wheel(wheel, omit_schema=True)
    assert any("missing Proof Kernel schema" in value for value in wheel_errors(wheel))


def test_proof_kernel_wheel_gate_rejects_missing_v4_closure(tmp_path: Path) -> None:
    wheel = tmp_path / "missing-closure.whl"
    closure = "zscope/core/validation/proof_kernel/closure.py"
    _wheel(wheel, omit_module=closure)

    assert any(closure in value for value in wheel_errors(wheel))


def test_proof_kernel_wheel_gate_rejects_claim_promotion_import(tmp_path: Path) -> None:
    wheel = tmp_path / "forbidden.whl"
    _wheel(wheel, forbidden_import="zscope.core.validation.claim_verifier")

    assert any("forbidden live authority" in value for value in wheel_errors(wheel))
