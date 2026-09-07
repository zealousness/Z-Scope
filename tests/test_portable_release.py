from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from scripts.portable.abi import audit, elf_machine, parse_readelf, relocation_errors
from scripts.portable.verify import COMMON_CHECKS, PROFILE_CHECKS, check_smoke, verify_matrix
from scripts.portable_release import read_lock


def test_webui_assets_are_local_pinned_and_tampering_fails(tmp_path):
    import shutil
    from html.parser import HTMLParser
    from urllib.parse import urlsplit
    from scripts.portable.web_assets import LOCK, VENDOR, verify

    root = Path(__file__).resolve().parents[1]
    lock = verify(root)

    class Assets(HTMLParser):
        urls = []

        def handle_starttag(self, tag, attrs):
            data = dict(attrs)
            if tag == "script" and "src" in data:
                self.urls.append(data["src"])
            if tag == "link" and data.get("rel") == "stylesheet":
                self.urls.append(data["href"])

    page = (root / "zscope/web/static/index.html").read_text(encoding="utf-8")
    assets = Assets()
    assets.feed(page)
    assert assets.urls and "@import" not in page
    for url in assets.urls:
        assert not urlsplit(url).scheme and not urlsplit(url).netloc
        assert Path(url).name in lock["files"]
    (tmp_path / LOCK).parent.mkdir(parents=True)
    shutil.copy2(root / LOCK, tmp_path / LOCK)
    shutil.copytree(root / VENDOR, tmp_path / VENDOR)
    (tmp_path / VENDOR / "alpine.js").write_text("tampered")
    with pytest.raises(ValueError, match="differs from its lock"):
        verify(tmp_path)


def test_abi_counts_imports_and_does_not_count_exported_versions():
    report = parse_readelf(
        """
Version definition section '.gnu.version_d' contains 1 entry:
  Name: GLIBC_2.99
Version needs section '.gnu.version_r' contains 1 entry:
  Name: GLIBC_2.34
  9: 0000000000 0 FUNC GLOBAL DEFAULT UND memcpy@GLIBC_2.14 (2)
 10: 0000000000 0 FUNC GLOBAL DEFAULT UND __isoc23_strtol@GLIBC_2.38 (3)
"""
    )
    assert report["glibc_required"] == "2.38"
    assert "GLIBC_2.99" not in report["requirements"]
    assert {"symbol": "__isoc23_strtol", "version": "GLIBC_2.38"} in report["symbols"]


def test_special_abi_markers_are_not_silently_dropped():
    text = "Version needs section '.gnu.version_r' contains 2 entries:\n  Name: GLIBC_ABI_DT_RELR\n  Name: GLIBC_PRIVATE\n"
    report = parse_readelf(text)
    assert report["glibc_required"] == "2.36"
    assert report["unknown_abi_markers"] == ["GLIBC_PRIVATE"]


def test_architecture_uses_elf_header_not_filename():
    header = b"\x7fELF\x02\x01" + bytes(12) + struct.pack("<H", 183)
    assert elf_machine(header) == 183


def test_relocation_audit_rejects_build_paths_and_host_python_shebang(tmp_path):
    script = tmp_path / "tool"
    script.write_bytes(b"#!/usr/bin/python3\npath = '/work/sources/compiler/lib'\n")
    script.chmod(0o755)
    errors = relocation_errors(script)
    assert any("shebang" in item for item in errors)
    assert any("build path" in item for item in errors)
    script.write_bytes(b"#!/usr/bin/env python3\nprint('relocatable')\n")
    assert relocation_errors(script) == []
    script.write_bytes(b"com/example/helper/Foo\x00CFLAGS=-I/helper/lib/include\x00")
    assert relocation_errors(script) == ["Embedded build path: /helper/"]
    script.write_bytes(b"com/example/helper/Foo\x00")
    assert relocation_errors(script) == []


def test_abi_rejects_empty_bundles_and_escaping_links(tmp_path):
    (tmp_path / "escape").symlink_to(tmp_path.parent)
    result = audit(tmp_path, "x86_64")
    assert result["passed"] is False
    assert any("escaping" in item for item in result["errors"])
    assert any("no runtime ELF" in item for item in result["errors"])


def smoke():
    checks = {name: True for name in COMMON_CHECKS | PROFILE_CHECKS["cpp"]}
    return {
        "archive_sha256": "a" * 64,
        "arch": "aarch64",
        "profile": "cpp",
        "execution": "qemu",
        "runs": [
            {
                "glibc": version,
                "passed": True,
                "checks": dict(checks),
                "network": "none",
                "uid": 1000,
                "bundle_mount": "ro",
            }
            for version in ("2.34", "2.38", "2.39")
        ],
    }


def test_smoke_requires_actual_architecture_matrix_and_no_degradation():
    evidence = smoke()
    check_smoke(evidence, "aarch64", "cpp", "a" * 64, "2.38")
    evidence["runs"][1]["checks"]["saber"] = False
    with pytest.raises(ValueError, match="Missing or failed"):
        check_smoke(evidence, "aarch64", "cpp", "a" * 64, "2.38")


def test_older_glibc_failure_requires_recorded_reason():
    evidence = smoke()
    evidence["runs"][0]["passed"] = False
    evidence["runs"][0]["failure_reason"] = "GLIBC_2.38 not found"
    check_smoke(evidence, "aarch64", "cpp", "a" * 64, "2.38")
    evidence["runs"][0].pop("failure_reason")
    with pytest.raises(ValueError, match="Unacceptable"):
        check_smoke(evidence, "aarch64", "cpp", "a" * 64, "2.38")


@pytest.mark.parametrize("check", ["clang-batch", "clang-batch-references", "clang-batch-cache"])
def test_cpp_smoke_requires_batch_extraction_and_cache(check):
    evidence = smoke()
    evidence["runs"][1]["checks"].pop(check)
    with pytest.raises(ValueError, match="Missing or failed"):
        check_smoke(evidence, "aarch64", "cpp", "a" * 64, "2.38")


def test_single_package_verification_cannot_replace_full_release(tmp_path, monkeypatch):
    from scripts.portable import verify

    (tmp_path / "release-manifest.json").write_text(json.dumps({"signature_status": "unsigned-local"}))
    calls = []

    def capture(directory, matrix, signed, inspect):
        calls.append((matrix, signed, inspect))
        return {"passed": True}

    monkeypatch.setattr(verify, "_verify_assets", capture)
    result = verify.verify_package(tmp_path, "x86_64", "cpp")
    assert result["formal_release"] is False
    assert calls[-1] == ({("x86_64", "cpp")}, False, True)
    verify.verify_matrix(tmp_path)
    assert calls[-1] == (verify.MATRIX, True, True)
    (tmp_path / "release-manifest.json").write_text(json.dumps({"signature_status": "signed"}))
    with pytest.raises(ValueError, match="only for unsigned"):
        verify.verify_package(tmp_path, "x86_64", "cpp")


def test_unsigned_local_manifest_cannot_pass_formal_release(tmp_path):
    (tmp_path / "release-manifest.json").write_text(
        json.dumps(
            {"schema_version": "zscope.release-assets.v2", "signature_status": "unsigned-local"}
        )
    )
    with pytest.raises(ValueError, match="signed, clean"):
        verify_matrix(tmp_path)


def test_checked_in_toolchain_is_immutable_and_keeps_llvm_versions_separate():
    lock = read_lock(Path(__file__).parents[1] / "requirements/portable/toolchain.lock.json")
    assert lock["sources"]["clangd"]["version"] == "llvmorg-22.1.7"
    assert lock["sources"]["llvm"]["version"] == "llvmorg-18.1.0"
    assert lock["sources"]["svf"]["version"] == "3.2"
    assert all("@sha256:" in image for image in lock["base_images"].values())


def test_download_never_accepts_truncated_response(tmp_path, monkeypatch):
    import io
    import hashlib
    from scripts.portable import download

    class Response(io.BytesIO):
        headers = {"Content-Length": "20"}

    class Opener:
        def open(self, *args, **kwargs):
            return Response(b"short")

    monkeypatch.setattr(download.urllib.request, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(download.time, "sleep", lambda seconds: None)
    entry = {
        "filename": "source.tar.gz",
        "url": "https://example.invalid/source",
        "sha256": hashlib.sha256(b"short").hexdigest(),
    }
    with pytest.raises(OSError, match="Truncated"):
        download.fetch_file(entry, tmp_path)
    assert not (tmp_path / entry["filename"]).exists()
