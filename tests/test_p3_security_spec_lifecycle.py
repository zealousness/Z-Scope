import json
from pathlib import Path

from scripts.check_p3_security_spec_lifecycle import check


def test_repository_security_spec_lifecycle_gate_passes() -> None:
    assert check() == []


def test_shadow_security_spec_mode_is_rejected_during_p5(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1]
    package = tmp_path / "zscope/semantics/security_specs"
    package.mkdir(parents=True)
    (package / "lifecycle.py").write_text(
        'SECURITY_SPEC_MODE = "shadow"\n' 'REVIEWER_IDENTITY_MODE = "unavailable_read_only"\n',
        encoding="utf-8",
    )
    (tmp_path / "zscope/config").mkdir(parents=True)
    design = tmp_path / "docs/design/zscope-2.0-security-architecture"
    design.mkdir(parents=True)
    manifest = json.loads(
        (source / "docs/design/zscope-2.0-security-architecture/design-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    manifest["phase_status"]["P5"] = "pending"
    (design / "design-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert "SecuritySpec mode must be authoritative during the P5 cutover" in check(tmp_path)


def test_user_controllable_security_spec_mode_is_rejected(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1]
    package = tmp_path / "zscope/semantics/security_specs"
    package.mkdir(parents=True)
    (package / "lifecycle.py").write_text(
        'SECURITY_SPEC_MODE = "authoritative"\n'
        'REVIEWER_IDENTITY_MODE = "unavailable_read_only"\n',
        encoding="utf-8",
    )
    config = tmp_path / "zscope/config"
    config.mkdir(parents=True)
    (config / "runtime.yaml").write_text("security_spec_mode: shadow\n", encoding="utf-8")
    design = tmp_path / "docs/design/zscope-2.0-security-architecture"
    design.mkdir(parents=True)
    manifest = json.loads(
        (source / "docs/design/zscope-2.0-security-architecture/design-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    (design / "design-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert any("user-controllable security_spec_mode" in value for value in check(tmp_path))
