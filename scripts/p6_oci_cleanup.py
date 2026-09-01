#!/usr/bin/env python3
"""Strict runner-owned recovery for hard-killed P6 scanner containers."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from zscope.benchmarking.isolation import (
    P6_OCI_CLEANUP_SCHEMA_VERSION,
    P6_OCI_CONCURRENCY_GROUP,
    P6_OCI_LABEL_ATTEMPT_ID,
    P6_OCI_LABEL_CONCURRENCY_GROUP,
    P6_OCI_LABEL_PHASE,
    P6_OCI_LABEL_REPOSITORY,
    P6_OCI_LABEL_SCHEMA,
    P6_OCI_LABEL_WORKFLOW_RUN_ATTEMPT,
    P6_OCI_LABEL_WORKFLOW_RUN_ID,
    P6OciCleanupScope,
    oci_runtime_environment,
)


_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTAINER_NAME_RE = re.compile(r"zscope-benchmark-([A-Za-z0-9_.-]{1,32})-[0-9a-f]{12}\Z")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z")
ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]


class P6OciCleanupError(RuntimeError):
    """Raised without embedding runtime output or inspected metadata."""


def _safe_environment() -> dict[str, str]:
    return oci_runtime_environment()


def _invoke(
    runner: ProcessRunner,
    argv: Sequence[str],
    *,
    accepted_returncodes: Sequence[int] = (0,),
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            [str(value) for value in argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=_safe_environment(),
        )
    except BaseException:
        raise P6OciCleanupError("P6 OCI cleanup runtime invocation failed") from None
    if result.returncode not in set(accepted_returncodes):
        raise P6OciCleanupError("P6 OCI cleanup runtime invocation failed")
    return result


def _runtime_path(runtime: str, *, which: Callable[[str], Optional[str]]) -> str:
    requested = str(runtime or "").strip()
    resolved = which(requested) if requested else None
    family = Path(str(resolved or requested)).name.lower()
    if family.endswith(".exe"):
        family = family[:-4]
    if not resolved or family not in {"podman", "docker"}:
        raise P6OciCleanupError("P6 OCI cleanup runtime is unavailable")
    return str(Path(resolved).resolve())


def _base_labels(repository: str) -> dict[str, str]:
    if _REPOSITORY_RE.fullmatch(repository) is None:
        raise P6OciCleanupError("P6 OCI cleanup repository identity is invalid")
    return {
        "io.zscope.role": "scanner",
        P6_OCI_LABEL_SCHEMA: P6_OCI_CLEANUP_SCHEMA_VERSION,
        P6_OCI_LABEL_CONCURRENCY_GROUP: P6_OCI_CONCURRENCY_GROUP,
        P6_OCI_LABEL_REPOSITORY: repository,
    }


def _list_ids(
    runner: ProcessRunner,
    runtime_path: str,
    labels: Mapping[str, str],
) -> list[str]:
    argv = [runtime_path, "ps", "--all", "--no-trunc"]
    for key, value in sorted(labels.items()):
        argv.extend(("--filter", f"label={key}={value}"))
    argv.extend(("--format", "{{.ID}}"))
    result = _invoke(runner, argv)
    identities = [
        line.strip().lower() for line in str(result.stdout or "").splitlines() if line.strip()
    ]
    if any(_CONTAINER_ID_RE.fullmatch(identity) is None for identity in identities) or len(
        set(identities)
    ) != len(identities):
        raise P6OciCleanupError("P6 OCI cleanup container enumeration is invalid")
    return identities


def _inspect(runner: ProcessRunner, runtime_path: str, identity: str) -> Mapping[str, Any]:
    result = _invoke(runner, (runtime_path, "inspect", identity))
    try:
        value = json.loads(str(result.stdout or ""))
    except (TypeError, json.JSONDecodeError):
        raise P6OciCleanupError("P6 OCI cleanup inspect result is invalid") from None
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, Mapping):
        raise P6OciCleanupError("P6 OCI cleanup inspect result is invalid")
    return value


def _validated_container_id(
    listed_id: str,
    inspect: Mapping[str, Any],
    *,
    expected_labels: Mapping[str, str],
) -> str:
    container_id = str(inspect.get("Id") or inspect.get("ID") or "").lower()
    raw_name = inspect.get("Name") or inspect.get("Names") or ""
    if isinstance(raw_name, list) and len(raw_name) == 1:
        raw_name = raw_name[0]
    name = str(raw_name).lstrip("/")
    config = inspect.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        raise P6OciCleanupError("P6 OCI cleanup labels are invalid")
    normalized_labels = {str(key): str(value) for key, value in labels.items()}
    name_match = _CONTAINER_NAME_RE.fullmatch(name)
    run_id = normalized_labels.get(P6_OCI_LABEL_WORKFLOW_RUN_ID, "")
    run_attempt = normalized_labels.get(P6_OCI_LABEL_WORKFLOW_RUN_ATTEMPT, "")
    attempt_id = normalized_labels.get(P6_OCI_LABEL_ATTEMPT_ID, "")
    phase = normalized_labels.get(P6_OCI_LABEL_PHASE, "")
    if (
        _CONTAINER_ID_RE.fullmatch(container_id) is None
        or container_id != listed_id
        or name_match is None
        or name_match.group(1) != phase
        or _POSITIVE_INTEGER_RE.fullmatch(run_id) is None
        or _POSITIVE_INTEGER_RE.fullmatch(run_attempt) is None
        or attempt_id != f"p6-{run_id}-{run_attempt}"
        or any(normalized_labels.get(key) != value for key, value in expected_labels.items())
    ):
        raise P6OciCleanupError("P6 OCI cleanup target identity is invalid")
    return container_id


def cleanup_p6_oci_scanners(
    *,
    runtime: str,
    mode: str,
    repository: str,
    workflow_run_id: str = "",
    workflow_run_attempt: str = "",
    attempt_id: str = "",
    process_runner: ProcessRunner = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> int:
    """Remove only containers whose inspected labels match one exact cleanup scope."""

    runtime_path = _runtime_path(runtime, which=which)
    labels = _base_labels(repository)
    if mode == "current":
        scope = P6OciCleanupScope.from_environment(
            {
                "GITHUB_REPOSITORY": repository,
                "GITHUB_RUN_ID": workflow_run_id,
                "GITHUB_RUN_ATTEMPT": workflow_run_attempt,
                "P6_ATTEMPT_ID": attempt_id,
            },
            process_environment={},
        )
        if scope is None:
            raise P6OciCleanupError("P6 OCI cleanup scope is missing")
        labels.update(
            {
                P6_OCI_LABEL_WORKFLOW_RUN_ID: scope.workflow_run_id,
                P6_OCI_LABEL_WORKFLOW_RUN_ATTEMPT: scope.workflow_run_attempt,
                P6_OCI_LABEL_ATTEMPT_ID: scope.attempt_id,
            }
        )
    elif mode != "stale":
        raise P6OciCleanupError("P6 OCI cleanup mode is invalid")

    identities = _list_ids(process_runner, runtime_path, labels)
    validated_ids = []
    for listed_id in identities:
        inspect = _inspect(process_runner, runtime_path, listed_id)
        validated_ids.append(_validated_container_id(listed_id, inspect, expected_labels=labels))
    for container_id in validated_ids:
        _invoke(process_runner, (runtime_path, "rm", "--force", container_id))
    if _list_ids(process_runner, runtime_path, labels):
        raise P6OciCleanupError("P6 OCI cleanup verification failed")
    return len(identities)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--mode", required=True, choices=("stale", "current"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-run-id", default="")
    parser.add_argument("--workflow-run-attempt", default="")
    parser.add_argument("--attempt-id", default="")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        removed = cleanup_p6_oci_scanners(
            runtime=args.runtime,
            mode=args.mode,
            repository=args.repository,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            attempt_id=args.attempt_id,
        )
    except (P6OciCleanupError, Exception):
        print("P6 OCI cleanup failed", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema_version": P6_OCI_CLEANUP_SCHEMA_VERSION,
                "mode": args.mode,
                "removed_count": removed,
                "verified": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
