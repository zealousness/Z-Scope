"""Daily scan-window CLI using the same durable scheduler as the WebUI.

Closing this observer does not cancel the saved schedule or its detached owner.
No user commands, API keys or shell fragments are saved in schedule policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description="Z-SCOPE 每日扫描时段守夜人")
    parser.add_argument("--config", default="zscope.yaml")
    parser.add_argument("--start", default="23:00", help="每日开始 HH:MM")
    parser.add_argument("--end", default="08:00", help="每日结束 HH:MM，可跨午夜")
    parser.add_argument("--timezone", default="Asia/Taipei")
    parser.add_argument("--scan-depth", choices=["fast", "balanced", "deep"], default="balanced")
    parser.add_argument("--request-id", help="同一标识重放同一计划；新计划请显式换标识")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("持久守夜人需在 Linux / WSL Linux 用户态运行")
    from zscope.orchestration.jobs.schedules import ScanScheduleService

    config = Path(args.config).resolve()
    policy = {
        "scan_depth": args.scan_depth,
        "end_mode": "complete",
        "daily_window": {"timezone": args.timezone, "start": args.start, "end": args.end},
    }
    signature = hashlib.sha256(
        (str(config) + json.dumps(policy, sort_keys=True)).encode()
    ).hexdigest()[:32]
    service = ScanScheduleService(config)
    reply = service.create(request_id=args.request_id or "night-watchman:" + signature, **policy)
    if reply.status_code >= 400:
        print(json.dumps(reply.payload, ensure_ascii=False), file=sys.stderr)
        return 1
    schedule_id = reply.payload["schedule"]["schedule_id"]
    print(f"持久计划 {schedule_id}：每天 {args.start}–{args.end} ({args.timezone})")
    print("关闭此观察窗口后后台继续运行。可在同一工程 WebUI 中查看或取消。")
    print("续作复用经输入核对的可恢复状态，不保证只执行剩余项。")
    previous = None
    try:
        while True:
            schedules = service.list().payload.get("schedules", [])
            row = next(item for item in schedules if item["schedule_id"] == schedule_id)
            summary = {
                key: row.get(key)
                for key in ("status", "job_status", "next_start_at", "window_end_at", "error")
            }
            if summary != previous:
                print(json.dumps(summary, ensure_ascii=False), flush=True)
                previous = summary
            if row["status"] in {"completed", "cancelled", "expired"}:
                return 0 if row["status"] == "completed" else 2
            if row["status"] in {"blocked", "failed"}:
                return 1
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n已退出观察，持久计划继续；取消请使用 WebUI。")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
