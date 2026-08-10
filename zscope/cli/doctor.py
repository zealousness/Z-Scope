"""Environment diagnostics for online and offline Z-SCOPE profiles."""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from ..config.config import ConfigLoader


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> Dict[str, Any]:
    return {"name": name, "ok": bool(ok), "required": required, "detail": detail}


@click.command()
@click.option(
    "--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--profile",
    type=click.Choice(["auto", "cpp", "java", "all"]),
    default="auto",
    show_default=True,
)
@click.option("--json-output", is_flag=True, help="Emit machine-readable diagnostics.")
def main(config_path: Optional[Path], profile: str, json_output: bool) -> None:
    """Check Python, toolchains, configuration, cache, and directory access."""

    checks: List[Dict[str, Any]] = []
    py_version = platform.python_version()
    checks.append(
        _check(
            "python>=3.9",
            sys.version_info >= (3, 9),
            f"{py_version} ({sys.executable})",
        )
    )
    checks.append(
        _check(
            "recommended-python",
            sys.version_info[:2] == (3, 13),
            "CPython 3.13 is the bundled/recommended runtime; 3.9-3.14 are verified",
            required=False,
        )
    )
    system = platform.system().lower()
    release = platform.release().lower()
    linux_userland = system == "linux"
    checks.append(
        _check(
            "linux-userland",
            linux_userland,
            f"{platform.system()} {platform.release()}"
            + (" (WSL)" if "microsoft" in release else ""),
        )
    )

    language = "auto"
    config = None
    if config_path:
        try:
            config = ConfigLoader.load(str(config_path))
            language = config.project.language
            checks.append(_check("configuration", True, str(config_path.resolve())))
        except Exception as exc:
            checks.append(_check("configuration", False, str(exc)))
    if profile == "auto":
        profile = "java" if language == "java" else "cpp"

    required_tools = []
    optional_tools = []
    if profile in {"cpp", "all"}:
        required_tools.extend(["gcc", "cmake", "clangd"])
        optional_tools.extend(["gclang", "get-bc"])
    if profile in {"java", "all"}:
        required_tools.extend(["java", "mvn", "joern"])
        optional_tools.append("codeql")
    for tool in dict.fromkeys(required_tools):
        found = shutil.which(tool)
        checks.append(_check(f"tool:{tool}", found is not None, found or "not found on PATH"))
    for tool in dict.fromkeys(optional_tools):
        found = shutil.which(tool)
        checks.append(
            _check(f"tool:{tool}", found is not None, found or "not found on PATH", required=False)
        )

    directories = [
        Path(os.environ.get("Z_SCOPE_CONFIG_HOME", "~/.config/zscope")).expanduser(),
        Path(os.environ.get("Z_SCOPE_CACHE_HOME", "~/.cache/zscope")).expanduser(),
    ]
    if config is not None:
        directories.append(Path(config.project.project_root))
    for directory in directories:
        parent = directory if directory.exists() else directory.parent
        checks.append(
            _check(
                f"writable:{directory}",
                parent.exists() and os.access(str(parent), os.W_OK),
                str(parent),
            )
        )

    if json_output:
        click.echo(json.dumps({"profile": profile, "checks": checks}, ensure_ascii=False, indent=2))
    else:
        for item in checks:
            status = "PASS" if item["ok"] else ("WARN" if not item["required"] else "FAIL")
            click.echo(f"{status:4} {item['name']}: {item['detail']}")
    if any(not item["ok"] and item["required"] for item in checks):
        raise click.exceptions.Exit(1)


if __name__ == "__main__":
    main()
