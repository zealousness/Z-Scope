"""P5 Hypothesis Hunter lifecycle boundary.

Hunter may register an unconfirmed candidate, but it never owns promotion or
terminal authority.
"""

HYPOTHESIS_HUNTER_MODE = "active"
ACTIVE_PRODUCT_EFFECT = "candidate_registration_only"


def require_active_contract(*, mode: str, active_product_effect: str) -> None:
    if mode != HYPOTHESIS_HUNTER_MODE or active_product_effect != ACTIVE_PRODUCT_EFFECT:
        raise ValueError("hypothesis_hunter_mode_is_not_configurable")


def assert_shadow_contract(*, mode: str, active_product_effect: str) -> None:
    """Compatibility name retained while callers migrate to P5 terminology."""

    require_active_contract(mode=mode, active_product_effect=active_product_effect)
