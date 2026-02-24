import sys
import os
import time

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope/zscope")
from zscope.retrieval.code_index import CodeIndex
from zscope.config.config import IndexingConfig
from pathlib import Path

def main():
    source_root = Path("/mnt/c/Users/10273/home/work/Z-Scope/test/junior/cache_module")
    project_root = source_root

    idx_cfg = IndexingConfig(
        backend="joern",
        joern_path="/mnt/c/Users/10273/home/work/Z-Scope/dependency/joern/joern",
        joern_server_host="127.0.0.1",
        joern_server_port=8080
    )

    print("Initializing CodeIndex...")
    index = CodeIndex(
        project_root=project_root,
        source_root=source_root,
        indexing_config=idx_cfg,
        wait_for_cpg=True
    )
    
    print("Wait for index...")
    index.ensure_index_ready()

    print("Fetching implementation of cache_get...")
    impl = index.get_function_impl("cache_get")
    if impl:
        print(f"Success! Signature: {impl.get('signature')}")
        print(f"File: {impl.get('file')}")
        code = impl.get('code', '')
        print(f"Code len: {len(code)}")
        print(f"Sample:\n{code[:80]}...")
    else:
        print("Failed to get implementation of cache_get!")

    index.close()

if __name__ == "__main__":
    main()
