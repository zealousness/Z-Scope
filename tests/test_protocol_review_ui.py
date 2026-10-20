"""Run real dashboard behavior with local fake transport; no browser/network."""

from pathlib import Path
import shutil
import subprocess

import pytest


def test_business_review_drafts_and_async_responses():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard JavaScript execution tests")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, "tests/fixtures/protocol_review_ui.cjs"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
