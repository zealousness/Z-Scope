
import os
import sys
import time
from pathlib import Path
import logging

# Add zscope to path
sys.path.append(str(Path(r"c:\Users\10273\home\work\Z-Scope\zscope").resolve()))

from zscope.common.lsp_client import LSPClient

logging.basicConfig(level=logging.INFO)

def verify_linux_style_progress():
    print("--- Linux-style (\r) Progress Verification Start ---")
    project_root = Path(r"c:\Users\10273\home\work\Z-Scope\test\cache_module").resolve()
    mock_script = Path(r"c:\Users\10273\home\work\Z-Scope\tmp\mock_linux_clangd.py").resolve()
    
    bat_path = Path(r"c:\Users\10273\home\work\Z-Scope\tmp\mock_linux_clangd.bat")
    with open(bat_path, "w") as f:
        f.write(f"@echo off\npython {mock_script}\n")
    
    print(f"Starting LSPClient with mock Linux-style (\r) server...")
    client = LSPClient(project_root, clangd_path=str(bat_path))
    
    success = client.start()
    print(f"\nLSP Start returned: {success}")
    
    if success:
        print("Monitoring output for 5 seconds (watch for real-time \r updates)...")
        time.sleep(5)
        client.stop()
        print("\n--- Verification Complete ---")

if __name__ == "__main__":
    verify_linux_style_progress()
