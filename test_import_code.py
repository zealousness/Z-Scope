import sys
sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope/zscope")
from zscope.common.joern_client import JoernClient

client = JoernClient(joern_path="/mnt/c/Users/10273/home/work/Z-Scope/dependency/joern/joern", host="127.0.0.1", port=8080)
if client.start_server():
    print("Server started")
    import time
    time.sleep(5)
    query = 'importCode("/mnt/c/Users/10273/home/work/Z-Scope/test/junior/cache_module")'
    print(f"Executing: {query}")
    res = client.query(query)
    print(f"Result without args: {res}")
    
    query2 = 'importCode("/mnt/c/Users/10273/home/work/Z-Scope/test/junior/cache_module", args=List("--compilation-database", "path"))'
    print(f"Executing: {query2}")
    res2 = client.query(query2)
    print(f"Result with args: {res2}")
    
    query3 = 'importCode.c(inputPath="/mnt/c/Users/10273/home/work/Z-Scope/test/junior/cache_module", args=List("--compilation-database", "path"))'
    print(f"Executing: {query3}")
    res3 = client.query(query3)
    print(f"Result with importCode.c args: {res3}")
    
    client.stop_server()
