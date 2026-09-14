#!/usr/bin/env python3
"""Install offline Java dependencies for Z-SCOPE."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse


CODEQL_ARCHIVE = "codeql-bundle-linux64.tar.gz"
MAVEN_ARCHIVE = "apache-maven-3.9.6-bin.tar.gz"
JDK_ARCHIVE = "jdk-21_linux-x64_bin.tar.gz"
JOERN_ARCHIVE = "joern-cli.zip"

DEFAULT_BUILDTOOLS_DIR = Path("/opt/buildtools")
DEFAULT_PROFILE_PATH = Path("/etc/profile")
DEFAULT_JDK_DIR_NAME = "jdk-21"
DEFAULT_MAVEN_DIR_NAME = "apache-maven-3.9.6"
DEFAULT_CODEQL_DIR_NAME = "codeql"
DEFAULT_JOERN_DIR_NAME = "joern-cli"
MIN_GLIBC_VERSION = (2, 38)
MIN_PYTHON_VERSION = (3, 9)
OS_RELEASE_PATHS = (Path("/etc/os-release"), Path("/usr/lib/os-release"))
PROBE_TIMEOUT_SECONDS = 30
HUAWEI_PYPI_INDEX_URL = "https://mirrors.tools.huawei.com/pypi/simple"
HUAWEI_MAVEN_MIRROR_URL = "http://mirrors.tools.huawei.com/maven/"
PIP_TRUSTED_HOST_ENV = "PIP_TRUSTED_HOST"

PROFILE_BLOCK_MARKER_START = "# >>> Z-SCOPE Java toolchain >>>"
PROFILE_BLOCK_MARKER_END = "# <<< Z-SCOPE Java toolchain <<<"
PROFILE_BLOCK = f"""{PROFILE_BLOCK_MARKER_START}
export JAVA_HOME=/opt/buildtools/jdk-21
export MAVEN_HOME=/opt/buildtools/apache-maven-3.9.6
export M2_HOME=$MAVEN_HOME
export CODEQL_HOME=/opt/buildtools/codeql
export JOERN_HOME=/opt/buildtools/joern-cli
export PATH=$JAVA_HOME/bin:$MAVEN_HOME/bin:$CODEQL_HOME:$JOERN_HOME:$JOERN_HOME/bin:$PATH
{PROFILE_BLOCK_MARKER_END}
"""


@dataclass
class StepResult:
    name: str
    status: str
    message: str = ""
    path: str = ""


class DeploymentError(RuntimeError):
    """Raised when a deployment step cannot complete."""


class Installer:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.tool_root = Path(args.tool_root).expanduser().resolve()
        self.buildtools_dir = Path(args.buildtools_dir).expanduser()
        self.profile_path = Path(args.profile_path).expanduser()
        self.jdk_dir = self.buildtools_dir / DEFAULT_JDK_DIR_NAME
        self.maven_dir = self.buildtools_dir / DEFAULT_MAVEN_DIR_NAME
        self.codeql_dir = self.buildtools_dir / DEFAULT_CODEQL_DIR_NAME
        self.joern_dir = self.buildtools_dir / DEFAULT_JOERN_DIR_NAME
        self.zscope_source = Path(args.zscope_source).expanduser().resolve()
        self.steps: list[StepResult] = []
        self._prepared_tool_root: Path | None = None
        self._temp_dir: tempfile.TemporaryDirectory[str] | None = None

    def close(self) -> None:
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def run(self) -> dict[str, Any]:
        self._ensure_supported_target()
        self._ensure_runtime_versions()
        self._prepare_tool_root()
        self._ensure_root_or_dry_run()
        self._install_jdk()
        self._install_maven()
        self._install_codeql()
        self._install_joern()
        self._install_zscope()
        self._configure_maven_mirror()
        self._write_profile_block()
        self._source_profile_once()
        payload = self.status_payload(success=True)
        if not self.args.dry_run:
            self._ensure_status_ok(payload)
        return payload

    def status_payload(self, *, success: bool | None = None) -> dict[str, Any]:
        probes = self._probe_statuses()
        symbol_versions = self._symbol_version_status()
        return {
            "success": success,
            "dry_run": bool(self.args.dry_run),
            "tool_root": str(self.tool_root),
            "paths": {
                "buildtools_dir": str(self.buildtools_dir),
                "jdk_dir": str(self.jdk_dir),
                "maven_dir": str(self.maven_dir),
                "codeql_dir": str(self.codeql_dir),
                "joern_dir": str(self.joern_dir),
                "zscope_source": str(self.zscope_source),
                "zscope_executable": self._zscope_executable(),
                "maven_settings": str(self.maven_dir / "conf" / "settings.xml"),
                "profile_path": str(self.profile_path),
            },
            "archives": self._archive_statuses(),
            "installed": self._installed_statuses(),
            "environment": runtime_status(),
            "probes": probes,
            "symbol_versions": symbol_versions,
            "status_ok": self._status_ok(probes, symbol_versions),
            "mirrors": {
                "pypi_index_url": self._pip_index_url(),
                "expected_pypi_index_url": HUAWEI_PYPI_INDEX_URL,
                "maven_mirror_configured": self._maven_mirror_configured(),
                "expected_maven_mirror_url": HUAWEI_MAVEN_MIRROR_URL,
            },
            "steps": [step.__dict__ for step in self.steps],
            "warnings": self._warnings(),
        }

    def _ensure_supported_target(self) -> None:
        if platform.system().lower() != "linux":
            raise DeploymentError("Java dependency deployment currently supports Linux targets only")

    def _ensure_runtime_versions(self) -> None:
        env = runtime_status()
        errors = []
        if not env["glibc_ok"]:
            errors.append(_glibc_error_message(env))
        if not env["python_ok"]:
            errors.append(
                f"Python 3.9 or newer is required, current version is {env['python_version']}. "
                "Please upgrade Python manually before running dependency deployment."
            )
        if errors:
            raise DeploymentError("; ".join(errors))

    def _ensure_root_or_dry_run(self) -> None:
        geteuid = getattr(os, "geteuid", None)
        if self.args.dry_run or geteuid is None:
            return
        if geteuid() != 0:
            raise DeploymentError("Please run as root; installation writes to /opt and /etc/profile")

    def _prepare_tool_root(self) -> Path:
        if self._prepared_tool_root is not None:
            return self._prepared_tool_root
        if self.tool_root.is_dir():
            self._prepared_tool_root = self.tool_root
            return self._prepared_tool_root
        if not self.tool_root.is_file():
            raise DeploymentError(f"Tool root not found: {self.tool_root}")
        self._temp_dir = tempfile.TemporaryDirectory(prefix="zscope_java_tools_")
        temp_root = Path(self._temp_dir.name)
        extract_archive(self.tool_root, temp_root)
        self._prepared_tool_root = temp_root
        return self._prepared_tool_root

    def _archive_statuses(self) -> dict[str, dict[str, Any]]:
        try:
            root = self._prepare_tool_root()
        except DeploymentError:
            root = self.tool_root
        archive_names = [CODEQL_ARCHIVE, MAVEN_ARCHIVE, JDK_ARCHIVE, JOERN_ARCHIVE]
        result = {}
        for name in archive_names:
            match = find_file(root, name)
            result[name] = {"present": match is not None, "path": str(match) if match else ""}
        return result

    def _installed_statuses(self) -> dict[str, bool]:
        return {
            "jdk": path_exists(self.jdk_dir / "bin" / "java"),
            "maven": path_exists(self.maven_dir / "bin" / "mvn"),
            "codeql": path_exists(self.codeql_dir / "codeql"),
            "joern": path_exists(self.joern_dir / "joern")
            or path_exists(self.joern_dir / "bin" / "joern"),
            "zscope": bool(self._zscope_executable()),
            "profile_block": self._profile_has_block(),
        }

    def _warnings(self) -> list[str]:
        warnings: list[str] = []
        if str(self.buildtools_dir) != "/opt/buildtools":
            warnings.append("Custom buildtools_dir is used; ensure runtime users source the generated profile block.")
        pypi_url = self._pip_index_url()
        if pypi_url and pypi_url != HUAWEI_PYPI_INDEX_URL:
            warnings.append(f"Current pip global.index-url is {pypi_url}; expected {HUAWEI_PYPI_INDEX_URL}.")
        return warnings

    def _install_jdk(self) -> None:
        if self._skip_if_installed("install_jdk", self.jdk_dir, ("bin/java",)):
            return
        archive = self._require_archive(JDK_ARCHIVE)
        self._install_archive_root(
            step_name="install_jdk",
            archive=archive,
            target=self.jdk_dir,
            required_relative=("bin/java",),
        )

    def _install_maven(self) -> None:
        if self._skip_if_installed("install_maven", self.maven_dir, ("bin/mvn", "conf/settings.xml")):
            return
        archive = self._require_archive(MAVEN_ARCHIVE)
        self._install_archive_root(
            step_name="install_maven",
            archive=archive,
            target=self.maven_dir,
            required_relative=("bin/mvn", "conf/settings.xml"),
        )

    def _install_codeql(self) -> None:
        if self._skip_if_installed("install_codeql", self.codeql_dir, ("codeql",)):
            return
        archive = self._require_archive(CODEQL_ARCHIVE)
        self._install_archive_root(
            step_name="install_codeql",
            archive=archive,
            target=self.codeql_dir,
            required_relative=("codeql",),
        )

    def _install_joern(self) -> None:
        if self._skip_if_installed("install_joern", self.joern_dir, ("joern", "bin/joern"), match_any=True):
            return
        archive = self._require_archive(JOERN_ARCHIVE)
        self._install_archive_root(
            step_name="install_joern",
            archive=archive,
            target=self.joern_dir,
            required_relative=("joern", "bin/joern"),
            match_any=True,
        )

    def _install_zscope(self) -> None:
        existing = self._zscope_executable()
        if existing and not self.args.force:
            self._record("install_zscope", "skipped", "Already installed", existing)
            return
        if not (self.zscope_source / "pyproject.toml").exists():
            raise DeploymentError(f"Z-SCOPE source not found or invalid: {self.zscope_source}")
        self._run(
            [sys.executable, "-m", "pip", "install", "-e", str(self.zscope_source)],
            step_name="install_zscope",
            cwd=self.zscope_source,
            env=pip_env_with_index_trusted_host(),
        )

    def _configure_maven_mirror(self) -> None:
        settings_path = self.maven_dir / "conf" / "settings.xml"
        if self.args.dry_run:
            self._record("configure_maven_mirror", "dry_run", "Would configure Huawei Cloud Maven mirror", str(settings_path))
            return
        if not settings_path.exists():
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            settings_path.write_text("<settings><mirrors /></settings>\n", encoding="utf-8")
        configure_maven_settings(settings_path)
        self._record("configure_maven_mirror", "ok", "Configured Huawei Cloud Maven mirror", str(settings_path))

    def _write_profile_block(self) -> None:
        block = self._profile_block_for_paths()
        if self.args.dry_run:
            self._record("write_profile", "dry_run", "Would update profile environment block", str(self.profile_path))
            return
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        existing = self.profile_path.read_text(encoding="utf-8") if self.profile_path.exists() else ""
        if PROFILE_BLOCK_MARKER_START in existing and PROFILE_BLOCK_MARKER_END in existing:
            before, rest = existing.split(PROFILE_BLOCK_MARKER_START, 1)
            _, after = rest.split(PROFILE_BLOCK_MARKER_END, 1)
            updated = before.rstrip() + "\n" + block + after.lstrip("\n")
        else:
            updated = existing.rstrip() + "\n\n" + block
        self.profile_path.write_text(updated, encoding="utf-8")
        self._record("write_profile", "ok", "Updated profile environment block", str(self.profile_path))

    def _profile_block_for_paths(self) -> str:
        if self.buildtools_dir == DEFAULT_BUILDTOOLS_DIR:
            return PROFILE_BLOCK
        return f"""{PROFILE_BLOCK_MARKER_START}
export JAVA_HOME={self.jdk_dir}
export MAVEN_HOME={self.maven_dir}
export M2_HOME=$MAVEN_HOME
export CODEQL_HOME={self.codeql_dir}
export JOERN_HOME={self.joern_dir}
export PATH=$JAVA_HOME/bin:$MAVEN_HOME/bin:$CODEQL_HOME:$JOERN_HOME:$JOERN_HOME/bin:$PATH
{PROFILE_BLOCK_MARKER_END}
"""

    def _source_profile_once(self) -> None:
        if self.args.dry_run:
            self._record("source_profile", "dry_run", "Would source profile environment block", str(self.profile_path))
            return
        if not self.profile_path.exists():
            raise DeploymentError(f"Profile path does not exist: {self.profile_path}")
        self._run(
            ["bash", "-lc", f"source {shlex.quote(str(self.profile_path))} >/dev/null"],
            step_name="source_profile",
        )

    def _install_archive_root(
        self,
        *,
        step_name: str,
        archive: Path,
        target: Path,
        required_relative: Sequence[str],
        match_any: bool = False,
    ) -> None:
        if target.exists() and not self.args.force and has_required(target, required_relative, match_any=match_any):
            self._record(step_name, "skipped", "Already installed", str(target))
            return
        if self.args.dry_run:
            self._record(step_name, "dry_run", f"Would extract {archive} to {target}", str(target))
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            shutil.rmtree(target)
        with tempfile.TemporaryDirectory(prefix=f"zscope_java_{step_name}_") as tmp:
            temp_root = Path(tmp)
            extract_archive(archive, temp_root)
            source_root = choose_root(temp_root, required_relative, match_any=match_any)
            if not source_root:
                raise DeploymentError(f"Unable to locate expected files in {archive}: {required_relative}")
            shutil.copytree(source_root, target, symlinks=True)
        self._restore_tool_permissions()
        self._record(step_name, "ok", f"Installed from {archive.name}", str(target))

    def _skip_if_installed(
        self,
        step_name: str,
        target: Path,
        required_relative: Sequence[str],
        *,
        match_any: bool = False,
    ) -> bool:
        if target.exists() and not self.args.force and has_required(target, required_relative, match_any=match_any):
            self._record(step_name, "skipped", "Already installed", str(target))
            return True
        return False

    def _pip_index_url(self) -> str:
        completed = subprocess.run(
            [sys.executable, "-m", "pip", "config", "get", "global.index-url"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            return ""
        return completed.stdout.strip()

    def _maven_mirror_configured(self) -> bool:
        settings_path = self.maven_dir / "conf" / "settings.xml"
        if not settings_path.exists():
            return False
        try:
            return maven_settings_has_huawei_mirror(settings_path)
        except (OSError, ET.ParseError):
            return False

    def _profile_has_block(self) -> bool:
        try:
            content = self.profile_path.read_text(encoding="utf-8")
        except OSError:
            return False
        return PROFILE_BLOCK_MARKER_START in content and PROFILE_BLOCK_MARKER_END in content

    def _zscope_executable(self) -> str:
        return shutil.which("zscope") or ""

    def _restore_tool_permissions(self) -> None:
        for path in (
            self.jdk_dir / "bin" / "java",
            self.maven_dir / "bin" / "mvn",
            self.codeql_dir / "codeql",
            self.joern_dir / "joern",
            self.joern_dir / "bin" / "joern",
        ):
            make_executable(path)
        if self.joern_dir.exists():
            for path in self.joern_dir.rglob("*"):
                if not path.is_file():
                    continue
                if "bin" in path.relative_to(self.joern_dir).parts or path.name.startswith("joern") or path.name.endswith(".sh"):
                    make_executable(path)

    def _tool_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "JAVA_HOME": str(self.jdk_dir),
                "MAVEN_HOME": str(self.maven_dir),
                "M2_HOME": str(self.maven_dir),
                "CODEQL_HOME": str(self.codeql_dir),
                "JOERN_HOME": str(self.joern_dir),
                "PATH": join_paths(
                    [
                        str(self.jdk_dir / "bin"),
                        str(self.maven_dir / "bin"),
                        str(self.codeql_dir),
                        str(self.joern_dir),
                        str(self.joern_dir / "bin"),
                        env.get("PATH", ""),
                    ]
                ),
            }
        )
        return env

    def _probe_statuses(self) -> dict[str, dict[str, Any]]:
        env = self._tool_env()
        probes = {
            "java": [str(self.jdk_dir / "bin" / "java"), "-version"],
            "mvn": [str(self.maven_dir / "bin" / "mvn"), "-version"],
            "codeql": [str(self.codeql_dir / "codeql"), "version"],
            "joern": [str(self.joern_dir / "bin" / "joern") if (self.joern_dir / "bin" / "joern").exists() else str(self.joern_dir / "joern"), "--help"],
            "zscope": [self._zscope_executable() or "zscope", "--help"],
        }
        return {name: run_probe(cmd, env=env) for name, cmd in probes.items()}

    def _symbol_version_status(self) -> dict[str, Any]:
        paths: list[Path] = []
        for root in (self.codeql_dir, self.joern_dir):
            if root.exists():
                paths.extend(path for path in root.rglob("*") if path.is_file())
        versions = max_symbol_versions(paths)
        env = runtime_status()
        errors: list[str] = []
        if version_gt(versions.get("GLIBC", ""), env.get("glibc_version", "")):
            errors.append(
                f"tool requires GLIBC_{versions.get('GLIBC')}, current glibc is {env.get('glibc_version') or 'unknown'}"
            )
        return {"tools": versions, "ok": not errors, "errors": errors}

    def _status_ok(self, probes: dict[str, dict[str, Any]], symbol_versions: dict[str, Any]) -> bool:
        return all(item.get("ok") for item in probes.values()) and bool(symbol_versions.get("ok"))

    def _ensure_status_ok(self, payload: dict[str, Any]) -> None:
        if payload.get("status_ok"):
            return
        failures = [name for name, item in payload.get("probes", {}).items() if not item.get("ok")]
        parts = [f"failed probes: {', '.join(failures)}"] if failures else []
        parts.extend(list((payload.get("symbol_versions") or {}).get("errors") or []))
        raise DeploymentError("; ".join(parts) or "deployment status check failed")

    def _require_archive(self, name: str) -> Path:
        archive = find_file(self._prepare_tool_root(), name)
        if not archive:
            raise DeploymentError(f"Required archive not found under {self.tool_root}: {name}")
        return archive

    def _record(self, name: str, status: str, message: str = "", path: str = "") -> None:
        self.steps.append(StepResult(name=name, status=status, message=message, path=path))

    def _run(
        self,
        cmd: Sequence[str],
        *,
        step_name: str,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        printable = " ".join(cmd)
        if self.args.dry_run:
            self._record(step_name, "dry_run", f"Would run: {printable}", str(cwd or ""))
            return
        completed = subprocess.run(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "").strip()
            raise DeploymentError(f"{printable} failed with code {completed.returncode}: {message}")
        self._record(step_name, "ok", (completed.stdout or "").strip() or f"Ran: {printable}", str(cwd or ""))


def configure_maven_settings(settings_path: Path) -> None:
    tree = ET.parse(settings_path)
    root = tree.getroot()
    namespace = element_namespace(root.tag)
    ET.register_namespace("", namespace) if namespace else None
    mirrors = child(root, "mirrors", namespace)
    if mirrors is None:
        mirrors = ET.SubElement(root, qname("mirrors", namespace))

    mirror = None
    for candidate in list(mirrors):
        id_node = child(candidate, "id", namespace)
        if id_node is not None and (id_node.text or "").strip() == "huaweicloud":
            mirror = candidate
            break
    if mirror is None:
        mirror = ET.SubElement(mirrors, qname("mirror", namespace))
    set_child_text(mirror, "id", "huaweicloud", namespace)
    set_child_text(mirror, "mirrorOf", "*", namespace)
    set_child_text(mirror, "url", HUAWEI_MAVEN_MIRROR_URL, namespace)
    indent_xml(root)
    tree.write(settings_path, encoding="utf-8", xml_declaration=True)


def maven_settings_has_huawei_mirror(settings_path: Path) -> bool:
    root = ET.parse(settings_path).getroot()
    namespace = element_namespace(root.tag)
    mirrors = child(root, "mirrors", namespace)
    if mirrors is None:
        return False
    for mirror in list(mirrors):
        mirror_id = text_of(child(mirror, "id", namespace))
        mirror_of = text_of(child(mirror, "mirrorOf", namespace))
        url = text_of(child(mirror, "url", namespace))
        if mirror_id == "huaweicloud" and mirror_of == "*" and url == HUAWEI_MAVEN_MIRROR_URL:
            return True
    return False


def element_namespace(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag[1:].split("}", 1)[0]
    return ""


def qname(name: str, namespace: str) -> str:
    return f"{{{namespace}}}{name}" if namespace else name


def child(node: ET.Element, name: str, namespace: str) -> ET.Element | None:
    return node.find(qname(name, namespace))


def set_child_text(node: ET.Element, name: str, value: str, namespace: str) -> None:
    target = child(node, name, namespace)
    if target is None:
        target = ET.SubElement(node, qname(name, namespace))
    target.text = value


def text_of(node: ET.Element | None) -> str:
    if node is None:
        return ""
    return (node.text or "").strip()


def indent_xml(root: ET.Element) -> None:
    try:
        ET.indent(root, space="  ")
    except AttributeError:
        return


def extract_archive(archive: Path, target_dir: Path) -> None:
    suffixes = "".join(archive.suffixes).lower()
    if suffixes.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            extract_zip_safely(zf, target_dir)
        return
    if suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            extract_tar_safely(tf, target_dir)
        return
    if suffixes.endswith(".tar"):
        with tarfile.open(archive, "r:") as tf:
            extract_tar_safely(tf, target_dir)
        return
    raise DeploymentError(f"Unsupported archive type: {archive}")


def extract_zip_safely(zf: zipfile.ZipFile, target_dir: Path) -> None:
    for info in zf.infolist():
        if not info.filename or info.filename.endswith("/"):
            safe_destination(target_dir, info.filename).mkdir(parents=True, exist_ok=True)
            continue
        dest = safe_destination(target_dir, info.filename)
        mode = (info.external_attr >> 16) & 0o777777
        dest.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(mode):
            link_target = zf.read(info).decode("utf-8")
            validate_link_target(target_dir, dest, link_target)
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            os.symlink(link_target, dest)
            continue
        with zf.open(info) as src, dest.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        if mode:
            dest.chmod(mode & 0o777)


def extract_tar_safely(tf: tarfile.TarFile, target_dir: Path) -> None:
    for member in tf.getmembers():
        safe_destination(target_dir, member.name)
        if member.issym() or member.islnk():
            validate_link_target(target_dir, target_dir / member.name, member.linkname)
    tf.extractall(target_dir)


def safe_destination(target_dir: Path, name: str) -> Path:
    candidate = target_dir / name
    resolved_target = target_dir.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    if Path(name).is_absolute() or ".." in Path(name).parts or not is_relative_to(resolved_candidate, resolved_target):
        raise DeploymentError(f"Unsafe archive member path: {name}")
    return candidate


def validate_link_target(target_dir: Path, link_path: Path, link_target: str) -> None:
    if Path(link_target).is_absolute():
        raise DeploymentError(f"Unsafe absolute symlink target in archive: {link_target}")
    resolved = (link_path.parent / link_target).resolve(strict=False)
    if not is_relative_to(resolved, target_dir.resolve()):
        raise DeploymentError(f"Unsafe symlink target in archive: {link_target}")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def choose_root(root: Path, required_relative: Sequence[str], *, match_any: bool = False) -> Path | None:
    candidates = [root] + [path for path in root.rglob("*") if path.is_dir()]
    for candidate in candidates:
        if has_required(candidate, required_relative, match_any=match_any):
            return candidate
    return None


def has_required(root: Path, required_relative: Sequence[str], *, match_any: bool = False) -> bool:
    checks = [path_is_file(root / item) for item in required_relative]
    return any(checks) if match_any else all(checks)


def find_file(root: Path, name: str) -> Path | None:
    if root.is_file() and root.name == name:
        return root
    if not root.exists() or not root.is_dir():
        return None
    direct = root / name
    if direct.exists():
        return direct
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    return matches[0] if matches else None


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def path_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def runtime_status() -> dict[str, Any]:
    libc_name, libc_version = platform.libc_ver()
    python_version = ".".join(str(part) for part in sys.version_info[:3])
    os_info = os_release_status()
    os_id = str(os_info.get("os_id") or "").lower()
    os_id_like = str(os_info.get("os_id_like") or "").lower()
    return {
        **os_info,
        "glibc_name": libc_name,
        "glibc_version": libc_version,
        "glibc_required": "2.38",
        "glibc_ok": libc_name == "glibc" and parse_version(libc_version) >= MIN_GLIBC_VERSION,
        "python_version": python_version,
        "python_required": ">=3.9",
        "python_ok": tuple(sys.version_info[:2]) >= MIN_PYTHON_VERSION,
        "is_euleros": os_id in {"euleros", "openeuler"} or "euler" in os_id_like,
    }


def _glibc_error_message(env: dict[str, Any]) -> str:
    current = env.get("glibc_version") or "unknown"
    if env.get("is_sles12_sp5"):
        return (
            f"SLES 12 SP5 requires glibc 2.38 or newer for the supplied Z-SCOPE toolchain, "
            f"current version is {current}. Please upgrade glibc from the internal SUSE source "
            "before running dependency deployment."
        )
    if env.get("is_euleros"):
        return (
            f"EulerOS requires glibc 2.38 or newer for the supplied Z-SCOPE toolchain, "
            f"current version is {current}. Please upgrade glibc from the internal EulerOS source "
            "before running dependency deployment."
        )
    return (
        f"glibc 2.38 or newer is required, current version is {current}. "
        "Please upgrade glibc manually before running dependency deployment."
    )


def os_release_status() -> dict[str, Any]:
    fields: dict[str, str] = {}
    for path in OS_RELEASE_PATHS:
        try:
            if path.exists():
                fields = parse_os_release(path.read_text(encoding="utf-8", errors="replace"))
                break
        except OSError:
            continue
    os_id = fields.get("ID", "")
    version_id = fields.get("VERSION_ID", "")
    return {
        "os_id": os_id,
        "os_id_like": fields.get("ID_LIKE", ""),
        "os_version_id": version_id,
        "os_pretty_name": fields.get("PRETTY_NAME", ""),
        "is_sles12_sp5": os_id.lower() in {"sles", "sle_hpc", "sles_sap"} and version_id.startswith("12.5"),
    }


def parse_os_release(content: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        fields[key.strip()] = value
    return fields


def parse_version(value: str) -> tuple[int, int]:
    parts = []
    for item in value.split("."):
        if not item.isdigit():
            break
        parts.append(int(item))
    while len(parts) < 2:
        parts.append(0)
    return parts[0], parts[1]


def join_paths(parts: Iterable[str]) -> str:
    return os.pathsep.join(part for part in parts if part)


def make_executable(path: Path) -> None:
    try:
        if path.exists():
            path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        return


def run_probe(cmd: Sequence[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    executable = cmd[0] if cmd else ""
    result = {"command": list(cmd), "returncode": None, "ok": False, "stdout": "", "stderr": ""}
    if not executable or not shutil.which(executable) and not Path(executable).exists():
        result["stderr"] = f"not found: {executable}"
        return result
    try:
        completed = subprocess.run(
            list(cmd),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["stderr"] = str(exc)
        return result
    result.update(
        {
            "returncode": completed.returncode,
            "ok": completed.returncode == 0,
            "stdout": trim_probe_output(completed.stdout),
            "stderr": trim_probe_output(completed.stderr),
        }
    )
    return result


def trim_probe_output(value: str, limit: int = 2000) -> str:
    text = (value or "").strip()
    return text[:limit]


SYMBOL_VERSION_RE = re.compile(rb"\b(GLIBCXX|GLIBC|CXXABI)_([0-9]+(?:\.[0-9]+)*)")


def max_symbol_versions(paths: Iterable[Path]) -> dict[str, str]:
    versions = {"GLIBC": "", "GLIBCXX": "", "CXXABI": ""}
    for path in paths:
        try:
            if not path.exists() or path.is_dir():
                continue
            data = path.read_bytes()
        except OSError:
            continue
        for family_b, version_b in SYMBOL_VERSION_RE.findall(data):
            family = family_b.decode("ascii")
            version = version_b.decode("ascii")
            if version_gt(version, versions.get(family, "")):
                versions[family] = version
    return versions


def version_gt(left: str, right: str) -> bool:
    if not left:
        return False
    if not right:
        return True
    return version_tuple(left) > version_tuple(right)


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def pip_env_with_index_trusted_host(base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env) if base_env is not None else os.environ.copy()
    host = pip_index_host(env.get("PIP_INDEX_URL", ""))
    if not host:
        return env
    trusted_hosts = split_trusted_hosts(env.get(PIP_TRUSTED_HOST_ENV, ""))
    if host not in trusted_hosts:
        trusted_hosts.append(host)
    env[PIP_TRUSTED_HOST_ENV] = " ".join(trusted_hosts)
    return env


def pip_index_host(index_url: str) -> str:
    parsed = urlparse(index_url.strip())
    return parsed.hostname or ""


def split_trusted_hosts(value: str) -> list[str]:
    return [part for part in re.split(r"[\s,]+", value.strip()) if part]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_tool_root() -> Path:
    return repo_root() / "tools" / "offline_dependencies"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install Z-SCOPE Java offline dependencies.")
    parser.add_argument(
        "--tool-root",
        default=str(default_tool_root()),
        help="Directory or bundle containing tool archives. Defaults to tools/offline_dependencies.",
    )
    parser.add_argument(
        "--zscope-source",
        default=str(repo_root()),
        help="Z-SCOPE source checkout to install with pip. Defaults to this repository.",
    )
    parser.add_argument("--buildtools-dir", default=str(DEFAULT_BUILDTOOLS_DIR))
    parser.add_argument("--profile-path", default=str(DEFAULT_PROFILE_PATH))
    parser.add_argument("--force", action="store_true", help="Replace existing installed tool directories.")
    parser.add_argument("--dry-run", action="store_true", help="Validate inputs and print planned steps only.")
    parser.add_argument("--status", action="store_true", help="Only report archive/install status.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    installer = Installer(args)
    try:
        payload = installer.status_payload() if args.status else installer.run()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print_human(payload)
        if args.status and not payload.get("status_ok"):
            return 1
        return 0
    except DeploymentError as exc:
        payload = installer.status_payload(success=False)
        payload["error"] = str(exc)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
            print_human(payload)
        return 1
    finally:
        installer.close()


def print_human(payload: dict[str, Any]) -> None:
    if payload.get("success") is not None:
        print(f"success: {payload['success']}")
    print(f"tool_root: {payload.get('tool_root', '')}")
    print("\nArchives:")
    for name, item in payload.get("archives", {}).items():
        status = "present" if item.get("present") else "missing"
        print(f"  {name}: {status} {item.get('path', '')}")
    print("\nInstalled:")
    for name, ok in payload.get("installed", {}).items():
        print(f"  {name}: {'yes' if ok else 'no'}")
    if payload.get("symbol_versions"):
        print("\nSymbol versions:")
        versions = payload["symbol_versions"]
        print(f"  tools: {versions.get('tools', {})}")
        for error in versions.get("errors", []):
            print(f"  error: {error}")
    if payload.get("probes"):
        print("\nProbes:")
        for name, probe in payload["probes"].items():
            status = "ok" if probe.get("ok") else "failed"
            print(f"  [{status}] {name}: {' '.join(probe.get('command', []))}")
            if probe.get("stderr"):
                print(f"    stderr: {probe['stderr']}")
    mirrors = payload.get("mirrors") or {}
    if mirrors:
        print("\nMirrors:")
        print(f"  pypi_index_url: {mirrors.get('pypi_index_url', '')}")
        print(f"  maven_mirror_configured: {mirrors.get('maven_mirror_configured')}")
    if payload.get("steps"):
        print("\nSteps:")
        for step in payload["steps"]:
            print(f"  [{step['status']}] {step['name']}: {step.get('message', '')}")
    if payload.get("warnings"):
        print("\nWarnings:")
        for warning in payload["warnings"]:
            print(f"  - {warning}")


if __name__ == "__main__":
    raise SystemExit(main())
