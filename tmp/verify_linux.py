
import os
import sys
import time
from pathlib import Path
import logging

# Add zscope to path (assuming mounted at /app/zscope)
sys.path.append("/app/zscope")

from zscope.common.lsp_client import LSPClient

logging.basicConfig(level=logging.INFO)

def verify_linux_progress():
    print("--- Linux Progress Verification Start ---")
    project_root = Path("/app").resolve()
    mock_script = "/app/tmp/mock_linux_clangd.py"
    
    # Simple wrapper to run mock
    bat_path = "/app/tmp/mock_linux_clangd.sh"
    with open(bat_path, "w") as f:
        f.write(f"#!/bin/bash\npython3 {mock_script}\n")
    os.chmod(bat_path, 0o755)
    
    print(f"Starting LSPClient in Linux mode with mock server...")
    client = LSPClient(project_root, clangd_path=bat_path)
    
    success = client.start()
    print(f"\nLSP Start returned: {success}")
    
    if success:
        print("Monitoring output for 5 seconds...")
        # The mock takes about 3 seconds
        time.sleep(5)
        client.stop()
        print("\n--- Verification Complete ---")

if __name__ == "__main__":
    verify_linux_progress()
