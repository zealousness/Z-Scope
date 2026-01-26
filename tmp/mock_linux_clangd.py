
import sys
import time
import json

def send_msg(msg):
    content = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(content)}\r\n\r\n")
    sys.stdout.write(content)
    sys.stdout.flush()

def main():
    try:
        # 1. Wait for initialize request
        send_msg({"jsonrpc": "2.0", "method": "window/logMessage", "params": {"message": "MOCK: Waiting for init"}})
        line = sys.stdin.readline()
        
        # 2. Send initialize response
        send_msg({
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "capabilities": {
                    "textDocumentSync": 2
                }
            }
        })
        
        # 3. Simulate indexing progress on stderr
        # We use \n here just to be absolutely sure it's not a \r issue in simulation
        sys.stderr.write("I[00:00:00.000] Indexing... [0/100]\n")
        sys.stderr.flush()
        time.sleep(1)
        
        sys.stderr.write("I[00:00:01.000] Indexing... [50/100]\n")
        sys.stderr.flush()
        time.sleep(1)
        
        sys.stderr.write("I[00:00:02.000] Indexing... [100/100] Done\n")
        sys.stderr.flush()
        time.sleep(1)
        
        # 4. Final log
        sys.stderr.write("I[00:00:03.000] Parsing finished.\n")
        sys.stderr.flush()
        
        # Keep alive for a bit
        time.sleep(5)
    except Exception as e:
        sys.stderr.write(f"MOCK ERROR: {e}\n")
        sys.stderr.flush()

if __name__ == "__main__":
    main()
