import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# Make sure we can import zscope
sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope/zscope")

from zscope.common.joern_client import JoernClient

def thread_query(cpgql):
    print(f"Thread running query: {cpgql}")
    client = JoernClient(host="127.0.0.1", port=8080)
    result = client.query(cpgql)
    print(f"Thread result: {str(result)[:100]}...")
    return result

def main():
    print("Starting Joern...")
    joern_path = "/mnt/c/Users/10273/home/work/Z-Scope/dependency/joern/joern"
    client = JoernClient(joern_path=joern_path, host="127.0.0.1", port=8080)
    if not client.start_server():
        print("Failed to start")
        sys.exit(1)
        
    time.sleep(5)
    print("Testing threaded queries...")
    pool = ThreadPoolExecutor(max_workers=2)
    futures = []
    
    # 1. The fallback regex query
    q1 = 'cpg.method.isExternal(false).map(m => Map("name" -> m.name)).take(2).l.toJson'
    futures.append(pool.submit(thread_query, q1))
    
    # 2. A normal method query
    q2 = 'cpg.method.name("main").l.toJson'
    futures.append(pool.submit(thread_query, q2))
    
    for f in futures:
        try:
            f.result()
        except Exception as e:
            print(f"Future error: {e}")
            
    client.stop_server()

if __name__ == "__main__":
    main()
