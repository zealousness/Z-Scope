"""Build/install the native TU indexer against a matching LLVM/Clang SDK."""

import argparse
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-prefix", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, default=Path("build/clang-indexer"))
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / "native" / "clang-indexer"
    compiler = args.llvm_prefix / "bin" / "clang++"
    # Preserve clang++ even when it is a symlink to clang: argv[0] selects C++ linking.
    compiler_option = [f"-DCMAKE_CXX_COMPILER={compiler.absolute()}"] if compiler.is_file() else []
    subprocess.run(
        [
            "cmake",
            "-S",
            str(source),
            "-B",
            str(args.build_dir),
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DLLVM_DIR={args.llvm_prefix}/lib/cmake/llvm",
            f"-DClang_DIR={args.llvm_prefix}/lib/cmake/clang",
            f"-DCMAKE_INSTALL_PREFIX={args.prefix.resolve()}",
        ]
        + compiler_option,
        check=True,
    )
    subprocess.run(
        ["cmake", "--build", str(args.build_dir), "--parallel", str(max(1, args.jobs))], check=True
    )
    subprocess.run(["cmake", "--install", str(args.build_dir)], check=True)


if __name__ == "__main__":
    main()
