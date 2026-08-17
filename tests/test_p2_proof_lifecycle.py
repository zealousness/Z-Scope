import json
from pathlib import Path

from scripts.check_p2_proof_lifecycle import check


def test_repository_proof_lifecycle_gate_passes() -> None:
    assert check() == []


def test_authoritative_mode_is_rejected_before_p5(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1]
    lifecycle = tmp_path / "zscope/core/validation/proof_kernel"
    lifecycle.mkdir(parents=True)
    (lifecycle / "lifecycle.py").write_text(
        'PROOF_KERNEL_MODE = "authoritative"\n', encoding="utf-8"
    )
    config = tmp_path / "zscope/config"
    config.mkdir(parents=True)
    design = tmp_path / "docs/design/zscope-2.0-security-architecture"
    design.mkdir(parents=True)
    manifest = json.loads(
        (source / "docs/design/zscope-2.0-security-architecture/design-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    manifest["phase_status"]["P5"] = "pending"
    (design / "design-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert "Proof Kernel mode must remain shadow until P5 is complete" in check(tmp_path)


def test_user_configurable_mode_is_rejected_before_p5(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1]
    lifecycle = tmp_path / "zscope/core/validation/proof_kernel"
    lifecycle.mkdir(parents=True)
    (lifecycle / "lifecycle.py").write_text('PROOF_KERNEL_MODE = "shadow"\n', encoding="utf-8")
    config = tmp_path / "zscope/config"
    config.mkdir(parents=True)
    (config / "runtime.py").write_text('proof_kernel_mode = "shadow"\n', encoding="utf-8")
    design = tmp_path / "docs/design/zscope-2.0-security-architecture"
    design.mkdir(parents=True)
    manifest = json.loads(
        (source / "docs/design/zscope-2.0-security-architecture/design-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    manifest["phase_status"]["P5"] = "pending"
    (design / "design-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert any("user-controllable proof_kernel_mode" in value for value in check(tmp_path))
