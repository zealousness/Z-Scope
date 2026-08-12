"""Retrieval backend package initialization."""

from ._clang_runtime_fixes import install_clang_runtime_fixes

install_clang_runtime_fixes()

__all__ = ["install_clang_runtime_fixes"]
