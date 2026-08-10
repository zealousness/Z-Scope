#!/usr/bin/env python3
"""Enforce package-version and Git-tag equality for release workflows."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def package_version() -> str:
    text = (ROOT / "zscope" / "_version.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not match:
        raise SystemExit("unable to read zscope._version.__version__")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default="")
    args = parser.parse_args()
    version = package_version()
    expected = f"v{version}"
    if args.tag and args.tag != expected:
        raise SystemExit(f"release tag {args.tag!r} must equal {expected!r}")
    print(version)


if __name__ == "__main__":
    main()
