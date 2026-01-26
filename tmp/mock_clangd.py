
import sys
import time
import json

def send_msg(msg):
    content = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(content)}\r\n\r\n")
    sys.stdout.write(content)
    sys.stdout.flush()

def main():
    # 1. Wait for initialize request
    line = sys.stdin.readline()
    # We ignore the content for now, just simulate success
    
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
    # These should be caught by _stderr_loop
    logs = [
        "I[22:42:16.123] Indexing... [1/100]",
        "I[22:42:17.456] Parsing: main.c",
        "I[22:42:18.789] Indexing: [50/100] files processed",
        "I[22:42:19.012] Scanning: include/header.h",
        "I[22:42:20.345] Indexing: 90%"
    ]
    
    for log in logs:
        sys.stderr.write(f"{log}\n")
        sys.stderr.flush()
        time.sleep(1)
        
    # 4. Simulate LSP progress on stdout
    # These should be caught by $/progress in _read_loop
    send_msg({
        "jsonrpc": "2.0",
        "method": "window/logMessage",
        "params": {
            "type": 3,
            "message": "Building index... (95%)"
        }
    })
    
    send_msg({
        "jsonrpc": "2.0",
        "method": "textDocument/clangd.fileStatus",
        "params": {
            "uri": "file:///path/to/final_check.c",
            "state": "Normalizing"
        }
    })

    print("Mock finished indexing", file=sys.stderr)
    time.sleep(5)

if __name__ == "__main__":
    main()
