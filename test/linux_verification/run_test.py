import os
import subprocess
import sys
import time
from pathlib import Path

def main():
    print("=== Z-SCOPE Real Linux Verification (SiliconFlow) ===")
    
    # 1. Environment Diagnostics
    project_dir = "/app/zscope/tests/cache_module"
    print(f"Current Directory: {os.getcwd()}")
    print(f"Project Directory: {project_dir}")
    
    if not os.path.exists(project_dir):
        print(f"  [✗] Project directory NOT FOUND: {project_dir}")
        sys.exit(1)
        
    print(f"Project Directory Contents: {os.listdir(project_dir)}")
    src_dir = os.path.join(project_dir, "src")
    if os.path.exists(src_dir):
        print(f"src Directory Contents: {os.listdir(src_dir)}")
    
    cdb_path = os.path.join(project_dir, "compile_commands.json")
    if os.path.exists(cdb_path):
        print(f"  [✓] compile_commands.json found at {cdb_path}")
        with open(cdb_path, 'r') as f:
            print("CDB Content Sample (first 200 chars):")
            print(f.read(200) + "...")
    else:
        print(f"  [✗] compile_commands.json NOT FOUND at {cdb_path}")
        sys.exit(1)

    os.chdir(project_dir)
    config_file = "zscope_linux.yaml"
    
    print(f"\nStarting analysis of cache_module using {config_file}...")
    
    # Run zscope CLI with verbose flag to capture more detail
    cmd = ["zscope", "--config", config_file, "--verbose"]
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1, 
        env=os.environ.copy()
    )
    
    progress_captured = False
    
    # Read output line by line
    for line in process.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        if "[LSP]" in line and not progress_captured:
            progress_captured = True
            
    process.wait()
    
    if process.returncode == 0:
        print("\n=== Analysis Completed Successfully ===")
        if os.path.exists("report.md"):
            print("  [✓] Generated report.md")
        else:
            print("  [✗] FAILED: report.md not found.")
            sys.exit(1)
    else:
        print(f"\n=== Analysis FAILED with exit code {process.returncode} ===")
        # Keep report check as it might contain partial info
        if os.path.exists("report.md"):
             print("  [Note] report.md exists despite failure.")
        sys.exit(1)

if __name__ == "__main__":
    main()
