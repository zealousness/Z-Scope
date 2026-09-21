"""Export the complete logical report in the historical JSON representation."""

from __future__ import annotations
import argparse
from pathlib import Path
from ..reporting.json_io import read_report, write_json_atomic


def main() -> None:
    parser = argparse.ArgumentParser(prog="zscope-report")
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--input", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--format", choices=["legacy-json"], required=True)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("export output must differ from the input artifact")
    write_json_atomic(args.output, read_report(args.input, immutable=True))


if __name__ == "__main__":
    main()
