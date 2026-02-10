import http.server
import socketserver
import json
from pathlib import Path
from typing import Any, Dict

PORT = 8000
WEB_DIR = Path(__file__).parent / "static"
REPORT_FILENAME = "zscope_batch_report.json"
CONFIG_FILENAME = "zscope.yaml"
ALLOWED_VALIDATION_STATUSES = {"validated", "pending", "rejected"}


def _empty_report() -> Dict[str, Any]:
    return {
        "issues": [],
        "issues_by_severity": {"critical": [], "high": [], "medium": [], "low": []},
    }


def _strip_json_code_fence(content: str) -> str:
    """Allow loading reports accidentally wrapped by markdown code fences."""
    stripped = content.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    if not lines:
        return stripped

    if lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def load_report():
    report_path = Path(REPORT_FILENAME)
    if not report_path.exists():
        return _empty_report()

    raw_content = report_path.read_text(encoding="utf-8", errors="ignore")
    sanitized = _strip_json_code_fence(raw_content)
    if not sanitized:
        return _empty_report()

    try:
        return json.loads(sanitized)
    except json.JSONDecodeError as exc:
        print(f"Warning: failed to parse report JSON: {exc}")
        return _empty_report()


def save_report(report):
    report_path = Path(REPORT_FILENAME)
    with report_path.open("w", encoding="utf-8") as f:
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

    # Legacy report shape
    for issue in report.get("issues", []):
        update_issue(issue)

    for issues in report.get("issues_by_severity", {}).values():
        for issue in issues:
            update_issue(issue)

    # Current report shape
    for issue in report.get("findings", []):
        update_issue(issue)


class ZScopeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _send_json(self, payload, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def end_headers(self):
        # Avoid stale dashboard cache causing old broken JS to persist in browser.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        if self.path == "/api/findings":
            report = load_report()
            findings = report.get("issues")
            if findings is None:
                findings = report.get("findings", [])
            self._send_json({"report": report, "findings": findings})
        elif self.path == "/api/config":
            config_path = Path(CONFIG_FILENAME)
            if config_path.exists():
                try:
                    content = config_path.read_text(encoding="utf-8")
                except OSError as exc:
                    self._send_json({"content": "", "error": str(exc)}, status=500)
                    return
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
                config_path = Path(CONFIG_FILENAME)
                config_path.write_text(content, encoding="utf-8")
                self._send_json({"success": True, "path": str(config_path)})
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
