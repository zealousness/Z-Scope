"""P5 Security Spec authority boundary."""

from __future__ import annotations


SECURITY_SPEC_MODE = "authoritative"
REVIEWER_IDENTITY_MODE = "unavailable_read_only"


def require_authoritative_mode(mode: str) -> None:
    if mode != SECURITY_SPEC_MODE:
        raise ValueError("security_spec_mode_is_not_configurable")


def require_shadow_mode(mode: str) -> None:
    """Compatibility name for callers migrated during the P5 cutover."""

    require_authoritative_mode(mode)


def reject_review_write() -> None:
    raise PermissionError("reviewer_identity_unavailable")
