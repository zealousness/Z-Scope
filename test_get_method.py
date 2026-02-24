import sys
import os
import time

# Ensure we use the right paths
sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope/zscope")

from zscope.common.joern_client import JoernClient

def main():
    print("Starting JoernClient...")
    joern_path = "/mnt/c/Users/10273/home/work/Z-Scope/dependency/joern/joern"
    client = JoernClient(joern_path=joern_path, host="127.0.0.1", port=8080)
    
    if not client.start_server():
        print("Failed to start server")
        sys.exit(1)
        
    time.sleep(5)
    
    source_path = "/mnt/c/Users/10273/home/work/Z-Scope/test/junior/cache_module"
    print(f"Importing CPG for {source_path}...")
    success = client.import_cpg(source_path, project_root=source_path)
    
    if not success:
        print("Failed to import CPG!")
        client.stop_server()
        sys.exit(1)
        
    print("CPG loaded successfully. Querying get_method for 'cache_get'...")
    method_data = client.get_method("cache_get")
    print(f"Result for get_method('cache_get'): {method_data}")
    
    # Try a raw query
    print("Querying raw method count...")
    count_data = client.query("cpg.method.isExternal(false).size")
    print(f"Total internal methods: {count_data}")
    
    client.stop_server()

if __name__ == "__main__":
    main()
