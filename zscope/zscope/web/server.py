import http.server
import socketserver
import json
import os
import sys
from pathlib import Path

PORT = 8000
WEB_DIR = Path(__file__).parent / "static"

class ZScopeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/api/findings":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            # Look for report.json in the current working directory
            report_path = Path("zscope_batch_report.json")
            if report_path.exists():
                with open(report_path, "r", encoding="utf-8") as f:
                    self.wfile.write(f.read().encode("utf-8"))
            else:
                self.wfile.write(json.dumps({"error": "Report not found", "findings": []}).encode("utf-8"))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/api/triage":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            feedback = json.loads(post_data)
            
            # Simple persistence for demo - in reality, this would update a DB
            feedback_path = Path(".zscope_feedback.jsonl")
            with open(feedback_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(feedback) + "\n")
                
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
        else:
            self.send_error(404)

def run_server():
    # Create static dir if not exists (though it should be bundled)
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    
    with socketserver.TCPServer(("", PORT), ZScopeHandler) as httpd:
        print(f"Z-SCOPE Dashboard available at http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.server_close()

if __name__ == "__main__":
    run_server()
