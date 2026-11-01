"""Record a real Linux C executable link for bounded cross-TU analysis."""

import argparse
from pathlib import Path
import shlex
import subprocess

from ..retrieval.link_targets import record_link


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--compile-commands", type=Path, required=True)
    parser.add_argument(
        "--cmake-link-file",
        type=Path,
        help=(
            "Read a generated CMake link.txt, retain its direct object members, "
            "and rebuild/record that exact target"
        ),
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- clang a.o b.o -o app")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    directory = Path.cwd()
    if args.cmake_link_file is not None:
        if command:
            parser.error("--cmake-link-file cannot be combined with an explicit command")
        try:
            link_file = args.cmake_link_file.resolve(strict=True)
            raw = shlex.split(link_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            parser.exit(1, f"Link not recorded: invalid CMake link file: {exc}\n")
        if not raw or "-o" not in raw:
            parser.exit(1, "Link not recorded: CMake link file has no direct output\n")
        output_index = raw.index("-o") + 1
        if output_index >= len(raw):
            parser.exit(1, "Link not recorded: CMake link output is missing\n")
        # CMake executes ``CMakeFiles/<target>.dir/link.txt`` from the build
        # directory, not from the link file's own directory.
        if link_file.parent.name.endswith(".dir") and link_file.parent.parent.name == "CMakeFiles":
            directory = link_file.parent.parent.parent
        else:
            parser.exit(1, "Link not recorded: unsupported CMake link file layout\n")

        def absolute(value: str) -> str:
            path = Path(value)
            return str(path if path.is_absolute() else (directory / path).resolve())

        objects = [absolute(value) for value in raw[1:] if value.endswith(".o")]
        command = [raw[0], *objects, "-o", absolute(raw[output_index])]
    try:
        result = record_link(
            args.project_root,
            args.compile_commands,
            command,
            directory=directory,
        )
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Link not recorded: {exc}\n")
    print(f"Recorded {result['output']} ({result['target_id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
