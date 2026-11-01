"""Navigation contract checks execute in Linux, without issuing real scans."""

from pathlib import Path
import os
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Quality checks run in Linux")
def test_dashboard_navigation_contract():
    result = subprocess.run(
        [shutil.which("node") or "node", "tests/fixtures/dashboard_navigation.cjs"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Browser checks run in Linux")
def test_dashboard_navigation_browser_routes():
    if not os.environ.get("ZSCOPE_UI_PLAYWRIGHT_MODULE"):
        pytest.skip("Set ZSCOPE_UI_PLAYWRIGHT_MODULE for shipped-page browser checks")
    result = subprocess.run(
        [shutil.which("node") or "node", "tests/fixtures/dashboard_navigation.cjs", "--browser"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
