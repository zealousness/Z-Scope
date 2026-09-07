"""gllvm child adapter: keep concurrent compiler diagnostics in separate files.

Run as a script using the current Python. Enable verbose diagnostics on every
child (gllvm strips -v from its bitcode invocation), without changing analysis
flags or exit semantics. Children remain in gllvm's group for cancellation.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> int:
    directory, compiler, *arguments = sys.argv[1:]
    original_arguments = list(arguments)
    option_end = arguments.index("--") if "--" in arguments else len(arguments)
    if "-v" not in arguments[:option_end]:
        arguments.insert(option_end, "-v")
    fd, filename = tempfile.mkstemp(prefix="clang-", suffix=".stderr.log", dir=directory)
    with os.fdopen(fd, "wb") as stderr:
        process = subprocess.run([compiler, *arguments], stderr=stderr)
    path = Path(filename)
    path.with_suffix(".json").write_text(
        json.dumps(
            {
                "compiler": compiler,
                "original_arguments": original_arguments,
                "effective_arguments": arguments,
                "exit_code": process.returncode,
                "stderr_path": str(path),
            }
        ),
        encoding="utf-8",
    )
    # Preserve ordinary gllvm logging, but use the isolated files for decisions.
    with path.open("rb") as stream:
        while block := stream.read(65536):
            sys.stderr.buffer.write(block)
    return process.returncode if process.returncode >= 0 else 128 - process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
