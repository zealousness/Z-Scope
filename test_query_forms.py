import sys
import os
import time

sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope/zscope")
from zscope.common.joern_client import JoernClient

def main():
    client = JoernClient(joern_path="/mnt/c/Users/10273/home/work/Z-Scope/dependency/joern/joern", host="127.0.0.1", port=8080)
    if not client.start_server():
        sys.exit(1)
        
    time.sleep(5)
    source_path = "/mnt/c/Users/10273/home/work/Z-Scope/test/junior/cache_module"
    client.import_cpg(source_path, project_root=source_path)
    
    from cpgqls_client import CPGQLSClient
    c = CPGQLSClient("127.0.0.1:8080")
    
    # 1. Complex query
    raw = c.execute('cpg.method.isExternal(false).map(m => Map("name" -> m.name)).take(2).l.toJson')
    stdout = raw['stdout']
    
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean = ansi_escape.sub('', stdout).strip()
    print("CLEAN STDOUT:")
    print(clean)
    
    client.stop_server()

if __name__ == "__main__":
    main()
