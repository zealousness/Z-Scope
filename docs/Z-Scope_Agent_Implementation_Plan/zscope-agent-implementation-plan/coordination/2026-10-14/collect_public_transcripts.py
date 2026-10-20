"""Read all public MCP transcript pages through the already running client."""
from __future__ import annotations

import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
SESSIONS = {
    "s08": "sess_66640fd67a", "s01": "sess_9669ed4555",
    "projection": "sess_5b2791bb4a", "disposition": "sess_8fa76506e8",
}
KINDS = "tool_call,tool_call_update"


def main() -> None:
    for label, session_id in SESSIONS.items():
        output = HERE / "health-transcripts" / label
        output.mkdir(parents=True, exist_ok=True)
        offset = 0
        pages = 0
        failures = []
        latest = None
        completed = []
        while True:
            request_id = f"full-tools-{label}-{offset}"
            target = HERE / "bridge-queue" / f"200-{request_id}.request.json"
            response = HERE / f"bridge-response-{request_id}.json"
            if not target.exists() and not response.exists():
                target.write_text(json.dumps({"id": request_id, "tool": "get_transcript",
                    "arguments": {"session_id": session_id, "offset": offset,
                                  "limit": 1000, "kinds": KINDS}}) + "\n", encoding="utf-8")
            started = time.monotonic()
            while not response.exists():
                if time.monotonic() - started > 60:
                    raise RuntimeError(f"public transcript response pending: {request_id}; preserve queue")
                time.sleep(0.2)
            value = json.loads(response.read_text(encoding="utf-8"))
            if value.get("ok") is not True:
                raise RuntimeError(f"public query failed: {request_id}")
            (output / f"{offset:06d}.json").write_text(
                json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")
            pages += 1
            for event in value.get("events", []):
                data = event.get("data") or {}
                latest = event.get("ts")
                if data.get("status") == "failed":
                    failures.append({"at": latest, "data": data})
                elif data.get("status") == "completed":
                    completed.append({"at": latest, "tool_call_id": data.get("tool_call_id"),
                                      "title": data.get("title")})
            if pages % 20 == 0:
                print(json.dumps({"session": label, "pages": pages, "next_offset": value.get("next_offset"),
                                  "has_more": value.get("has_more")}), flush=True)
            if not value.get("has_more"):
                break
            next_offset = value.get("next_offset")
            if not isinstance(next_offset, int) or next_offset <= offset:
                raise RuntimeError("non-progressing public pagination; stop")
            offset = next_offset
        summary = {"session_id": session_id, "kinds": KINDS, "pages": pages,
                   "total_matching": value.get("total_matching"), "has_more": value.get("has_more"),
                   "latest_at": latest, "failures": failures, "completed_tail": completed[-5:],
                   "tool_content_complete": False,
                   "limitation": "Bridge drops content and truncates rawOutput; these pages cannot restore it"}
        (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"session": label, "pages": pages, "total_matching": summary["total_matching"],
                          "has_more": summary["has_more"], "latest_at": latest, "failed_tools": len(failures)}), flush=True)


if __name__ == "__main__":
    main()
