"""Record a real Linux C executable link for bounded cross-TU analysis."""

import argparse
from pathlib import Path
import subprocess

from ..retrieval.link_targets import record_link


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--compile-commands", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- clang a.o b.o -o app")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        result = record_link(args.project_root, args.compile_commands, command)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Link not recorded: {exc}\n")
    print(f"Recorded {result['output']} ({result['target_id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
