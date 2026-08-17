"""P2 lifecycle constants. Authority is forbidden until the P5 gate closes."""

PROOF_KERNEL_MODE = "shadow"


def assert_shadow_mode(mode: str) -> None:
    if mode != PROOF_KERNEL_MODE:
        raise ValueError("proof_kernel_authority_requires_p5_complete")
