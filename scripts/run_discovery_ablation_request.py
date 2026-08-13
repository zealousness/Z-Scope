#!/usr/bin/env python3
"""Execute one hash-bound D0-D4 request through an explicit scanner adapter."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.discovery_ablation import (
    DiscoveryAblationError,
    DiscoveryAblationExecutorLike,
    execute_discovery_ablation_request,
    load_discovery_ablation_run_request,
)


def _load_executor(reference: str) -> DiscoveryAblationExecutorLike:
    module_name, separator, attribute = str(reference or "").partition(":")
    if not separator or not module_name or not attribute:
        raise DiscoveryAblationError("executor must use package.module:callable")
    value: Any = getattr(importlib.import_module(module_name), attribute)
    if isinstance(value, type):
        value = value()
    if not callable(value) and not callable(getattr(value, "execute", None)):
        raise DiscoveryAblationError("executor is not callable and has no execute() method")
    return cast(DiscoveryAblationExecutorLike, value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--expected-request-sha256", required=True)
    parser.add_argument("--arm-catalog", type=Path)
    parser.add_argument(
        "--execution-mode",
        required=True,
        choices=("non-formal-in-process", "formal-rootless-oci"),
    )
    parser.add_argument("--executor", help="package.module:callable (non-formal mode only)")
    parser.add_argument("--oci-image", help="Pinned image@sha256 digest for formal mode")
    parser.add_argument("--executor-sha256", required=True)
    parser.add_argument("--usage-sidecar", required=True, type=Path)
    parser.add_argument("--expected-usage-sidecar-sha256")
    parser.add_argument("--report-output", required=True, type=Path)
    parser.add_argument("--execution-output", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.execution_mode == "formal-rootless-oci":
            image = str(args.oci_image or "")
            digest = image.rpartition("@sha256:")[2]
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise DiscoveryAblationError(
                    "formal ablation requires an immutable image@sha256:<64 lowercase hex>"
                )
            raise DiscoveryAblationError(
                "formal discovery ablation is fail-closed in this package.module adapter; "
                "the protected benchmark control plane must execute the pinned image through "
                "RootlessOciExecutor with sealed input/cache/output mounts"
            )
        if not args.executor:
            raise DiscoveryAblationError("non-formal in-process mode requires --executor")
        if args.oci_image:
            raise DiscoveryAblationError("--oci-image is only valid for formal-rootless-oci")
        if args.usage_sidecar.resolve().parent != args.report_output.resolve().parent:
            raise DiscoveryAblationError(
                "usage sidecar and report output must share an artifact directory"
            )
        request = load_discovery_ablation_run_request(
            args.request,
            expected_request_sha256=args.expected_request_sha256,
            catalog_path=args.arm_catalog,
        )
        if request["executor_sha256"] != args.executor_sha256:
            raise DiscoveryAblationError("external executor SHA-256 mismatch")
        report, execution = execute_discovery_ablation_request(
            request,
            executor=_load_executor(args.executor),
            expected_request_sha256=args.expected_request_sha256,
            usage_sidecar_path=args.usage_sidecar,
            expected_usage_sidecar_sha256=args.expected_usage_sidecar_sha256,
            catalog_path=args.arm_catalog,
        )
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.execution_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        args.execution_output.write_text(
            json.dumps(execution, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (DiscoveryAblationError, ImportError, AttributeError, OSError, TypeError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "schema_version": execution["schema_version"],
                "arm_id": execution["arm_id"],
                "trial_index": execution["trial_index"],
                "run_id": execution["run_id"],
                "execution_path": execution["execution_path"],
                "consumed_tokens": execution["report_contract"]["consumed_tokens"],
                "report_sha256": execution["report_sha256"],
                "execution_sha256": execution["execution_sha256"],
                "execution_mode": "non_formal_in_process",
                "answer_free_attested": False,
                "formal_eligible": False,
                "release_eligible": False,
                "report_output": str(args.report_output),
                "execution_output": str(args.execution_output),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
