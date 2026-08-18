"""P4 authority boundary frozen until the P5 cutover."""

HYPOTHESIS_HUNTER_MODE = "shadow"
ACTIVE_PRODUCT_EFFECT = "none"


def assert_shadow_contract(*, mode: str, active_product_effect: str) -> None:
    if mode != HYPOTHESIS_HUNTER_MODE or active_product_effect != ACTIVE_PRODUCT_EFFECT:
        raise ValueError("hypothesis_hunter_authority_requires_p5")
