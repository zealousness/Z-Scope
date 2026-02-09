import http.server
import socketserver
import json
from pathlib import Path

PORT = 8000
WEB_DIR = Path(__file__).parent / "static"
REPORT_PATH = Path("zscope_batch_report.json")
CONFIG_PATH = Path("zscope.yaml")
ALLOWED_VALIDATION_STATUSES = {"validated", "pending", "rejected"}


def load_report():
    if REPORT_PATH.exists():
        with REPORT_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {"issues": [], "issues_by_severity": {"critical": [], "high": [], "medium": [], "low": []}}


def save_report(report):
    with REPORT_PATH.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def issue_key(issue):
    return (
        issue.get("id"),
        issue.get("function"),
        issue.get("location"),
        issue.get("subcategory"),
    )


def normalize_validation(issue):
    status = issue.get("validation_status")
    if status not in ALLOWED_VALIDATION_STATUSES:
        status = "pending"
    reasoning = issue.get("validation_reasoning")
    return status, reasoning


def apply_validation_updates(report, updates):
    update_map = {issue_key(issue): normalize_validation(issue) for issue in updates}

    def update_issue(issue):
        key = issue_key(issue)
        if key in update_map:
            status, reasoning = update_map[key]
            issue["validation_status"] = status
            issue["validation_reasoning"] = reasoning

    for issue in report.get("issues", []):
        update_issue(issue)

    for issues in report.get("issues_by_severity", {}).values():
        for issue in issues:
            update_issue(issue)


class ZScopeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _send_json(self, payload, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_GET(self):
        if self.path == "/api/findings":
            report = load_report()
            self._send_json({"report": report, "findings": report.get("issues", [])})
        elif self.path == "/api/config":
            if CONFIG_PATH.exists():
                content = CONFIG_PATH.read_text(encoding="utf-8")
                self._send_json({"content": content})
            else:
                self._send_json({"content": ""})
        else:
            super().do_GET()

    def do_POST(self):
        if self.path in {"/api/config", "/api/save_findings"}:
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data or b"{}")
            except json.JSONDecodeError:
                self._send_json({"success": False, "error": "Invalid JSON"}, status=400)
                return

            if self.path == "/api/config":
                content = payload.get("content", "")
                CONFIG_PATH.write_text(content, encoding="utf-8")
                self._send_json({"success": True})
            else:
                report = load_report()
                updates = payload.get("issues", [])
                if not isinstance(updates, list):
                    self._send_json({"success": False, "error": "Issues must be a list"}, status=400)
                    return
                apply_validation_updates(report, updates)
                save_report(report)
                self._send_json({"success": True})
        else:
            self.send_error(404)


def run_server():
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
