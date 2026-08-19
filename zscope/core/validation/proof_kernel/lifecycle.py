"""P5 Proof Engine lifecycle boundary.

The cutover is intentionally a source-level invariant.  There is no runtime
configuration flag that can restore the pre-P5 shadow or compatibility
authority paths.
"""

PROOF_KERNEL_MODE = "authoritative"


def require_authoritative_mode(mode: str) -> None:
    if mode != PROOF_KERNEL_MODE:
        raise ValueError("proof_kernel_mode_is_not_configurable")


# Read-only import compatibility for P2/P3 artifacts.  Calling the old guard
# with ``shadow`` is deliberately rejected by the P5 runtime.
def assert_shadow_mode(mode: str) -> None:
    require_authoritative_mode(mode)
