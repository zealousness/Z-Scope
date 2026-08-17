"""P3 lifecycle authority boundary."""

from __future__ import annotations


SECURITY_SPEC_MODE = "shadow"
REVIEWER_IDENTITY_MODE = "unavailable_read_only"


def require_shadow_mode(mode: str) -> None:
    if mode != "shadow":
        raise ValueError("security_spec_authority_requires_p5_complete")


def reject_review_write() -> None:
    raise PermissionError("reviewer_identity_unavailable")
