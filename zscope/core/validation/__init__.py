from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .pipeline import PreValidationDecision, ValidationOutcome, ValidationPipeline

if TYPE_CHECKING:
    from .runner import ValidationRunner

__all__ = [
    "PreValidationDecision",
    "ValidationOutcome",
    "ValidationPipeline",
    "ValidationRunner",
]


def __getattr__(name: str) -> Any:
    """Load the orchestration-heavy runner only when explicitly requested.

    ``decision_trace`` imports the small terminal-authority module.  Eagerly
    importing ``runner`` here made that path recurse through
    ``runtime_authority -> decision_trace -> validation.__init__ -> runner``
    before ``decision_trace`` had finished defining its public helpers.
    Keeping the package convenience export lazy preserves the public API
    without coupling proof data models to scan orchestration.
    """

    if name == "ValidationRunner":
        from .runner import ValidationRunner

        return ValidationRunner
    raise AttributeError(name)
