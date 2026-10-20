"""Collect fresh public receipts through the existing owner clients only."""
from __future__ import annotations

import json
from pathlib import Path
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
RUN = uuid4().hex[:12]
OUT = HERE / "current-public" / RUN
TASKS = {
    "s01-cdb-coverage": ("task_054e1eb1e6", "sess_c3c6c01381", HERE / "route-check"),
    "s08-fair-queue": ("task_54d185892a", "sess_a3dc643fae", HERE / "route-check"),
    "s08-atomic-request": ("task_96ea0f4092", "sess_b2d3c1d8e8", HERE / "route-check"),
}


def query(client: Path, label: str, tool: str, arguments: dict) -> dict:
    request_id = f"current-{RUN}-{label}"
    request = client / "bridge-queue" / f"300-{request_id}.request.json"
    response = client / f"bridge-response-{request_id}.json"
    request.write_text(json.dumps({"id": request_id, "tool": tool,
                                  "arguments": arguments}) + "\n", encoding="utf-8")
    started = time.monotonic()
    while not response.exists():
        if time.monotonic() - started > 60:
            raise RuntimeError(f"read-only public query pending: {request_id}")
        time.sleep(0.2)
    value = json.loads(response.read_text(encoding="utf-8"))
    (OUT / f"{label}.json").write_text(json.dumps(value, ensure_ascii=False, indent=2)
                                      + "\n", encoding="utf-8")
    if value.get("ok") is not True:
        raise RuntimeError(f"public query unsuccessful: {request_id}")
    return value


def transcript(client: Path, label: str, session: str, kinds: str, offset: int) -> dict:
    pages = 0
    events = []
    older = sorted((HERE / "current-public").glob(f"*/{label}-{kinds.replace(',', '-')}-summary.json"),
                   key=lambda p: p.stat().st_mtime_ns)
    if older:
        prior = json.loads(older[-1].read_text(encoding="utf-8"))
        if prior.get("session_id") == session and prior.get("kinds") == kinds and prior.get("has_more") is False:
            offset = prior["next_offset"]
    start = offset
    while True:
        value = query(client, f"{label}-{kinds.replace(',', '-')}-{offset}",
                      "get_transcript", {"session_id": session, "offset": offset,
                                         "limit": 1000, "kinds": kinds})
        pages += 1
        events.extend(value.get("events", []))
        if not value.get("has_more"):
            break
        next_offset = value.get("next_offset")
        if not isinstance(next_offset, int) or next_offset <= offset:
            raise RuntimeError("non-progressing public transcript cursor")
        offset = next_offset
    summary = {"session_id": session, "kinds": kinds, "start_offset": start,
               "next_offset": value.get("next_offset"), "pages": pages,
               "total_matching": value.get("total_matching"), "has_more": False,
               "events_read": len(events), "latest_at": events[-1].get("ts") if events else None,
               "failed_tools": [e for e in events if (e.get("data") or {}).get("status") == "failed"],
               "completed_tail": [e for e in events if (e.get("data") or {}).get("status") == "completed"][-3:]}
    (OUT / f"{label}-{kinds.replace(',', '-')}-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k not in {"failed_tools", "completed_tail"}},
                     ensure_ascii=False), flush=True)
    return summary


def main() -> None:
    OUT.mkdir(parents=True)
    print(str(OUT), flush=True)
    for label, (task, session, client) in TASKS.items():
        state = query(client, f"{label}-state", "check_task", {"task_id": task})
        print(json.dumps({"task": label, "status": state.get("status"),
                          "error": state.get("error"), "silent_for_sec": state.get("silent_for_sec"),
                          "observed_model": state.get("observed_model")}), flush=True)
        result = query(client, f"{label}-result", "get_result",
                       {"task_id": task, "max_chars": 60000})
        print(json.dumps({"task": label, "result_source": result.get("result_source"),
                          "result_complete": result.get("result_complete"),
                          "has_more": result.get("has_more"), "usage": result.get("usage")}), flush=True)
    for label, (_task, session, client) in TASKS.items():
        transcript(client, label, session, "tool_call,tool_call_update", 0)
        transcript(client, label, session, "permission", 0)
        transcript(client, label, session, "message_chunk", 0)


if __name__ == "__main__":
    main()
