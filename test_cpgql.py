import sys
import os
import time
from urllib.request import urlopen, Request
from zscope.common.joern_client import JoernClient
from cpgqls_client import CPGQLSClient
import traceback

def main():
    print("Starting Joern...")
    client = JoernClient(joern_path="/mnt/c/Users/10273/home/work/Z-Scope/dependency/joern/joern", host="127.0.0.1", port=8080)
    if not client.start_server():
        print("Failed to start")
        sys.exit(1)
    
    time.sleep(5)
    print("Joern started. Testing raw HTTP reachability...")
    try:
         req = Request("http://127.0.0.1:8080/query")
         res = urlopen(req)
         print(f"HTTP reachable. Code: {res.getcode()}")
    except Exception as e:
         print(f"HTTP test error (expected POST only, or 401 maybe): {e}")

    print("Testing CPGQLS client...")
    try:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        
        # Simulate exactly what Z-Scope does now to ensure NO_PROXY bypass works
        old_http = os.environ.get("HTTP_PROXY")
        old_https = os.environ.get("HTTPS_PROXY")
        old_no = os.environ.get("NO_PROXY")
        os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"
        
        c = CPGQLSClient("127.0.0.1:8080")
        res = c.execute("cpg.method.l.size")
        print(f"Success! {res}")
        
        if old_http is not None: os.environ["HTTP_PROXY"] = old_http
        if old_https is not None: os.environ["HTTPS_PROXY"] = old_https
        if old_no is not None: os.environ["NO_PROXY"] = old_no
        elif "NO_PROXY" in os.environ: del os.environ["NO_PROXY"]
        
    except Exception as e:
        print("CPGQLS failure:")
        traceback.print_exc()

    client.stop_server()

if __name__ == '__main__':
    main()
