#!/usr/bin/env python3
"""Validate the installed release dependency set against an explicit license policy."""

from __future__ import annotations

import argparse
import json
import re
from importlib import metadata
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

LOCKED_REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)")
LICENSE_ALIASES = {
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "mit license": "MIT",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
}
CLASSIFIER_PREFIX = "License :: OSI Approved :: "


def canonicalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def canonicalize_license(value: str) -> str:
    compact = " ".join(value.strip().split())
    return LICENSE_ALIASES.get(compact.casefold(), compact)


def parse_locked_requirements(path: Path) -> Dict[str, str]:
    packages: Dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = LOCKED_REQUIREMENT.match(line.strip())
        if not match:
            continue
        name = canonicalize_name(match.group(1))
        version = match.group(2)
        if name in packages:
            raise ValueError(f"duplicate locked requirement {name!r} at line {line_number}")
        packages[name] = version
    if not packages:
        raise ValueError(f"no exact requirements found in {path}")
    return packages


def load_policy(path: Path) -> Dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("license policy schema_version must be 1")
    raw_packages = payload.get("packages")
    if not isinstance(raw_packages, dict) or not raw_packages:
        raise ValueError("license policy packages must be a non-empty object")
    packages: Dict[str, str] = {}
    for raw_name, raw_license in raw_packages.items():
        if not isinstance(raw_name, str) or not isinstance(raw_license, str):
            raise ValueError("license policy package names and licenses must be strings")
        name = canonicalize_name(raw_name)
        if name in packages:
            raise ValueError(f"duplicate normalized package in license policy: {name}")
        packages[name] = canonicalize_license(raw_license)
    return packages


def _classifier_licenses(classifiers: Iterable[str]) -> List[str]:
    values = []
    for classifier in classifiers:
        if classifier.startswith(CLASSIFIER_PREFIX):
            values.append(canonicalize_license(classifier[len(CLASSIFIER_PREFIX) :]))
    return values


def installed_license(package_name: str) -> Optional[str]:
    package_metadata = metadata.metadata(package_name)
    expression = package_metadata.get("License-Expression")
    if expression and expression.upper() != "UNKNOWN":
        return canonicalize_license(expression)

    declared = package_metadata.get("License")
    if declared and declared.upper() != "UNKNOWN" and len(declared) < 200:
        return canonicalize_license(declared)

    classifiers = _classifier_licenses(package_metadata.get_all("Classifier") or [])
    if len(classifiers) == 1:
        return classifiers[0]
    if classifiers:
        return " OR ".join(sorted(set(classifiers)))
    return None


def check_policy(locked: Mapping[str, str], approved: Mapping[str, str]) -> List[str]:
    errors: List[str] = []
    locked_names = set(locked)
    approved_names = set(approved)
    for name in sorted(locked_names - approved_names):
        errors.append(f"{name}: missing from license policy")
    for name in sorted(approved_names - locked_names):
        errors.append(f"{name}: policy entry is not present in the release lock")

    for name in sorted(locked_names & approved_names):
        try:
            installed_version = metadata.version(name)
            observed_license = installed_license(name)
        except metadata.PackageNotFoundError:
            errors.append(f"{name}: locked dependency is not installed")
            continue
        if installed_version != locked[name]:
            errors.append(
                f"{name}: installed version {installed_version!r} does not match lock {locked[name]!r}"
            )
        if observed_license is None:
            errors.append(f"{name}: installed distribution has no usable license metadata")
        elif observed_license != approved[name]:
            errors.append(
                f"{name}: observed license {observed_license!r} is not approved "
                f"(expected {approved[name]!r})"
            )
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        locked = parse_locked_requirements(args.requirements)
        approved = load_policy(args.policy)
        errors = check_policy(locked, approved)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"dependency license policy error: {exc}")
        return 2
    if errors:
        print("dependency license policy failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"dependency license policy passed for {len(locked)} locked packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
