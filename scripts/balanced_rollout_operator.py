#!/usr/bin/env python3
"""Apply one audited observation to the persistent balanced-rollout state.

This is a deliberately narrow operator boundary.  It reads rollout data only
from explicit files, never invokes commands, and obtains the signing secret
only from the dedicated management environment variable.  The secret is never
accepted as a CLI argument or included in output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.orchestration.rollout import (  # noqa: E402
    BalancedRolloutController,
    ObservationWindow,
    RolloutDecision,
    RolloutState,
    RolloutStateError,
    rollout_management_key_from_environment,
)


RESULT_SCHEMA_VERSION = "zscope.rollout-operator-result.v1"
MAX_WINDOW_BYTES = 1024 * 1024


class OperatorInputError(ValueError):
    """Raised when an operator-supplied file violates the CLI contract."""


def _reject_json_constant(value: str) -> NoReturn:
    raise OperatorInputError(f"window JSON contains unsupported numeric constant: {value}")


def _object_without_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OperatorInputError(f"window JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _read_window(path: Path) -> Tuple[ObservationWindow, str]:
    if path.is_symlink() or not path.is_file():
        raise OperatorInputError("window file must be an existing regular file, not a symlink")
    raw = path.read_bytes()
    if not raw:
        raise OperatorInputError("window file must not be empty")
    if len(raw) > MAX_WINDOW_BYTES:
        raise OperatorInputError(f"window file exceeds {MAX_WINDOW_BYTES} bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OperatorInputError("window file must be strict UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise OperatorInputError(f"window file is not valid JSON: {exc}") from exc
    return ObservationWindow.from_dict(value), hashlib.sha256(raw).hexdigest()


def _validate_state_path(path: Path, *, must_exist: bool) -> None:
    if path.is_symlink():
        raise OperatorInputError("state file must not be a symlink")
    if path.exists() and not path.is_file():
        raise OperatorInputError("state path must be a regular file")
    if must_exist and not path.is_file():
        raise OperatorInputError(
            "state file does not exist; run the initialize operation before recording a window"
        )


def _state_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _result(
    *,
    operation: str,
    decision: RolloutDecision,
    state: RolloutState,
    state_path: Path,
    state_sha256: Optional[str] = None,
    previous_state_sha256: Optional[str] = None,
    window_file_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "operation": operation,
        "decision": decision.to_dict(),
        "state_sha256": state_sha256 or _state_sha256(state_path),
        "stage": state.stage,
        "effective_depth": state.effective_depth,
        "recommended_balanced_percent": state.recommended_balanced_percent,
        "updated_at": state.updated_at,
    }
    if previous_state_sha256 is not None:
        result["previous_state_sha256"] = previous_state_sha256
    if window_file_sha256 is not None:
        result["window_file_sha256"] = window_file_sha256
    return result


def _add_audit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--reason", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)

    initialize = subparsers.add_parser(
        "initialize",
        help="Create or validate the telemetry-only rollout state.",
        allow_abbrev=False,
    )
    _add_audit_arguments(initialize)

    record = subparsers.add_parser(
        "record",
        help="Validate and record exactly one completed observation window.",
        allow_abbrev=False,
    )
    _add_audit_arguments(record)
    record.add_argument("--window-file", type=Path, required=True)
    record.add_argument(
        "--expected-state-sha256",
        required=True,
        help="Exact SHA-256 of the state file read by the protected control plane.",
    )
    return parser


def run(args: argparse.Namespace) -> Dict[str, Any]:
    state_path = Path(args.state_file)
    management_key = rollout_management_key_from_environment(required=True)
    controller = BalancedRolloutController(state_path, management_key=management_key)
    if args.operation == "initialize":
        _validate_state_path(state_path, must_exist=False)
        state = controller.initialize(owner=args.owner, reason=args.reason)
        decision = state.decisions[-1]
        return _result(
            operation="initialize",
            decision=decision,
            state=state,
            state_path=state_path,
        )
    if args.operation == "record":
        _validate_state_path(state_path, must_exist=True)
        window, window_sha256 = _read_window(Path(args.window_file))
        decision, state, previous_sha256, state_sha256 = controller.record_window_cas(
            window,
            expected_state_sha256=args.expected_state_sha256,
            owner=args.owner,
            reason=args.reason,
        )
        return _result(
            operation="record",
            decision=decision,
            state=state,
            state_path=state_path,
            state_sha256=state_sha256,
            previous_state_sha256=previous_sha256,
            window_file_sha256=window_sha256,
        )
    raise OperatorInputError(f"unsupported operation: {args.operation}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except (OSError, OperatorInputError, RolloutStateError) as exc:
        print(f"balanced rollout operator error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
