"""Run the answer-free P6 synthetic replay from a native Linux/WSL checkout."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from zscope.benchmarking.p6_synthetic_replay import (
    SyntheticReplayError,
    assert_answer_free_payload,
    failure_result,
    run_synthetic_replay,
)


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one non-formal, answer-free P6 synthetic replay.",
    )
    parser.add_argument("--config", required=True, type=_absolute_path)
    parser.add_argument("--api-key-file", required=True, type=_absolute_path)
    parser.add_argument("--work-root", required=True, type=_absolute_path)
    parser.add_argument("--output", required=True, type=_absolute_path)
    return parser


def _write_result(path: Path, value: Any) -> None:
    assert_answer_free_payload(value)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SyntheticReplayError("input", "input_binding_failure")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise SyntheticReplayError("input", "input_binding_failure")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
        handle.write("\n")
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_synthetic_replay(
            source_config_path=args.config,
            api_key_file=args.api_key_file,
            work_root=args.work_root,
        )
        _write_result(args.output, result)
    except SyntheticReplayError as exc:
        try:
            _write_result(args.output, failure_result(exc))
        except Exception:
            pass
        print(exc.public_line(), file=sys.stderr)
        return 2
    except Exception:
        error = SyntheticReplayError("internal", "internal_failure")
        try:
            _write_result(args.output, failure_result(error))
        except Exception:
            pass
        print(error.public_line(), file=sys.stderr)
        return 2
    print("stage=complete; class=none:0; count=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
