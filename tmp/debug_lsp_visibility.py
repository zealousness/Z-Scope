
import os
import sys
import threading
import time
from pathlib import Path
import logging

# Add zscope to path
sys.path.append(str(Path(r"c:\Users\10273\home\work\Z-Scope\zscope").resolve()))

from zscope.common.lsp_client import LSPClient

logging.basicConfig(level=logging.DEBUG)

def test_lsp_visibility():
    project_root = Path(r"c:\Users\10273\home\work\Z-Scope\test\cache_module").resolve()
    # Ensure compile_commands.json exists or simulate a large project environment
    
    print(f"Testing LSP visibility for {project_root}")
    client = LSPClient(project_root)
    
    # Override _read_loop and _stderr_loop to be extra verbose
    original_read = client._read_loop
    original_stderr = client._stderr_loop
    
    def verbose_stderr():
        print("[DEBUG] Stderr thread started")
        while client._running and client.process and client.process.stderr:
            line = client.process.stderr.readline()
            if not line: break
            raw = line.decode("utf-8", errors="replace").strip()
            print(f"[RAW-STDERR] {raw}")
            # Still call logic but we want to see if we get ANY raw output
    
    client._stderr_loop = verbose_stderr
    
    success = client.start()
    print(f"LSP Start result: {success}")
    
    if success:
        print("Waiting for 30 seconds to see if logs appear...")
        time.sleep(30)
        client.stop()

if __name__ == "__main__":
    test_lsp_visibility()
