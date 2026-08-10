#!/usr/bin/env python3
"""Repo-local Java structure frontend MVP.

This CLI emits the same JSON contract expected from structure sidecars. It is
intentionally dependency-light so the boundary can be tested without Maven
downloads in CI. Production sidecars live under tools/java-structure-spoon and
tools/java-structure-javaparser; this script is a builtin/debug helper.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.retrieval.java_models import JavaClassRecord  # noqa: E402
from zscope.retrieval.java_source_extractor import JavaSourceExtractor  # noqa: E402


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Java source structure as Z-SCOPE JSON.")
    parser.add_argument("source_root", nargs="?", default=".", help="Java project or source root.")
    parser.add_argument(
        "--frontend",
        default="javaparser",
        choices=["spoon", "javaparser", "builtin", "auto"],
        help="Frontend name to stamp into emitted records.",
    )
    parser.add_argument(
        "--project-root",
        default="",
        help="Build root for Maven/Gradle metadata discovery. Defaults to source_root.",
    )
    parser.add_argument(
        "--classpath",
        default="",
        help="Explicit classpath separated by the platform path separator.",
    )
    parser.add_argument(
        "--classpath-command",
        nargs="+",
        default=[],
        help="Optional command that prints classpath entries.",
    )
    args = parser.parse_args(argv)

    source_root = Path(args.source_root).resolve()
    project_root = Path(args.project_root).resolve() if args.project_root else source_root
    classes = JavaSourceExtractor(frontend=args.frontend).extract(source_root)
    payload = {
        "frontend": args.frontend,
        "build": _build_metadata(project_root, args.classpath, args.classpath_command),
        "classes": [_class_to_json(item) for item in classes],
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def _build_metadata(
    project_root: Path, classpath: str, classpath_command: List[str]
) -> Dict[str, Any]:
    entries = _explicit_classpath(classpath)
    entries.extend(_classpath_from_command(classpath_command, project_root))
    maven = _maven_metadata(project_root)
    entries.extend(maven.get("classpath_entries", []))
    gradle = _gradle_metadata(project_root)
    entries.extend(gradle.get("classpath_entries", []))
    return {
        "project_root": str(project_root),
        "build_tools": [
            name for name, enabled in (("maven", bool(maven)), ("gradle", bool(gradle))) if enabled
        ],
        "classpath_entries": _dedupe(entries),
        "maven": maven,
        "gradle": gradle,
    }


def _explicit_classpath(value: str) -> List[str]:
    if not value:
        return []
    return [part for part in value.split(os.pathsep) if part]


def _classpath_from_command(command: List[str], project_root: Path) -> List[str]:
    if not command:
        return []
    try:
        proc = subprocess.run(
            command,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    raw = proc.stdout.replace("\n", os.pathsep)
    return _explicit_classpath(raw)


def _maven_metadata(project_root: Path) -> Dict[str, Any]:
    pom = project_root / "pom.xml"
    if not pom.exists():
        return {}
    try:
        root = ET.parse(pom).getroot()
    except Exception:
        return {"pom": str(pom), "parse_error": True, "classpath_entries": []}
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0] + "}"
    properties = _maven_properties(root, ns)
    dependencies = []
    for dep in root.findall(f".//{ns}dependencies/{ns}dependency"):
        group_id = _child_text(dep, ns, "groupId")
        artifact_id = _child_text(dep, ns, "artifactId")
        version = _resolve_maven_property(_child_text(dep, ns, "version"), properties)
        scope = _child_text(dep, ns, "scope")
        if not group_id or not artifact_id:
            continue
        dependencies.append(
            {
                "group_id": group_id,
                "artifact_id": artifact_id,
                "version": version,
                "scope": scope,
                "coordinate": ":".join(part for part in [group_id, artifact_id, version] if part),
            }
        )
    return {
        "pom": str(pom),
        "source_roots": [str(project_root / "src/main/java"), str(project_root / "src/test/java")],
        "classpath_entries": [
            "maven:" + dep["coordinate"]
            for dep in dependencies
            if dep.get("scope") not in {"test", "provided"}
        ],
        "dependencies": dependencies,
    }


def _maven_properties(root: ET.Element, ns: str) -> Dict[str, str]:
    props: Dict[str, str] = {}
    props_node = root.find(f"{ns}properties")
    if props_node is None:
        return props
    for child in list(props_node):
        name = child.tag.split("}", 1)[-1]
        if child.text:
            props[name] = child.text.strip()
    return props


def _child_text(node: ET.Element, ns: str, name: str) -> str:
    child = node.find(f"{ns}{name}")
    return (child.text or "").strip() if child is not None else ""


def _resolve_maven_property(value: str, properties: Dict[str, str]) -> str:
    if value.startswith("${") and value.endswith("}"):
        return properties.get(value[2:-1], value)
    return value


def _gradle_metadata(project_root: Path) -> Dict[str, Any]:
    files = [
        path
        for path in [project_root / "build.gradle", project_root / "build.gradle.kts"]
        if path.exists()
    ]
    if not files:
        return {}
    entries: List[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if any(
                line.startswith(prefix)
                for prefix in ("implementation", "api", "compileOnly", "runtimeOnly")
            ):
                entries.append("gradle:" + line)
    return {
        "files": [str(path) for path in files],
        "source_roots": [str(project_root / "src/main/java"), str(project_root / "src/test/java")],
        "classpath_entries": entries,
    }


def _class_to_json(record: JavaClassRecord) -> Dict[str, Any]:
    return {
        "name": record.name,
        "full_name": record.full_name,
        "fullName": record.full_name,
        "package": record.package,
        "file": record.file,
        "start_line": record.start_line,
        "end_line": record.end_line,
        "kind": record.kind,
        "annotations": [item.to_backend_dict() for item in record.annotations],
        "fields": dict(record.fields),
        "methods": [method.to_method_metadata() for method in record.methods],
    }


def _dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
