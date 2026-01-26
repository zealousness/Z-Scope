
import os
import sys
import time
from pathlib import Path
import logging

# Add zscope to path
sys.path.append(str(Path(r"c:\Users\10273\home\work\Z-Scope\zscope").resolve()))

from zscope.common.lsp_client import LSPClient

logging.basicConfig(level=logging.INFO)

def verify_progress_display():
    project_root = Path(r"c:\Users\10273\home\work\Z-Scope\test\cache_module").resolve()
    mock_script = Path(r"c:\Users\10273\home\work\Z-Scope\tmp\mock_clangd.py").resolve()
    
    # We use 'python' as the executable and pass the script as the first argument
    # To trick LSPClient, we can pass the whole command if we want, but LSPClient joins it.
    # Actually, let's just make a small wrapper .bat or change the start method slightly.
    # Simpler: Create a .bat
    bat_path = Path(r"c:\Users\10273\home\work\Z-Scope\tmp\mock_clangd.bat")
    with open(bat_path, "w") as f:
        f.write(f"@echo off\npython {mock_script}\n")
    
    print(f"Verifying LSP progress display using mock server...")
    client = LSPClient(project_root, clangd_path=str(bat_path))
    
    success = client.start()
    print(f"\nLSP Start returned: {success}")
    
    if success:
        print("Waiting for mock indexing to finish...")
        # The mock takes about 5 seconds to finish its logs
        time.sleep(10)
        client.stop()
        print("\nVerification complete.")

if __name__ == "__main__":
    verify_progress_display()
