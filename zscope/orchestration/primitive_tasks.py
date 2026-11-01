"""Durable primitive preparation tasks; no scan report authority is stored here."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from typing import Any

from ..config.config import ConfigLoader
from ..config.project_semantics import canonical_digest
from ..config.semantics_workflow import SemanticsConflict, project_activity, revision
from .jobs.identity import probe_process, read_process_start_ticks, system_boot_id
from .primitive_preparation import PreparationCancelled, run_preparation

ACTIVE = {"queued", "running", "publishing", "cancelling"}


class PrimitiveTasks:
    def __init__(self, config_path: Path):
        self.config_path = Path(config_path).resolve()
        self.root = self.config_path.parent
        self.directory = self.root / ".zscope_snapshots" / "semantics"
        self.db = self.directory / (
            "tasks-" + canonical_digest(str(self.config_path))[:16] + ".sqlite3"
        )

    @contextmanager
    def connection(self):
        if not self.directory.resolve().is_relative_to(self.root):
            raise SemanticsConflict("任务状态目录不能指向工程外。")
        self.directory.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db, timeout=15) as con:
            con.row_factory = sqlite3.Row
            con.execute(
                "CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, request_id TEXT UNIQUE, payload TEXT, data TEXT)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS events (cursor INTEGER PRIMARY KEY AUTOINCREMENT, task TEXT, data TEXT)"
            )
            con.commit()
            con.execute("BEGIN IMMEDIATE")
            yield con

    def _put(self, con, task):
        con.execute(
            "UPDATE tasks SET data=? WHERE id=?", (json.dumps(task, ensure_ascii=False), task["id"])
        )

    def _event(self, con, task, stage, details=None):
        con.execute(
            "INSERT INTO events(task,data) VALUES (?,?)",
            (
                task["id"],
                json.dumps(
                    {
                        "stage": stage,
                        "details": details or {},
                        "at": time.time(),
                        "elapsed_seconds": round(time.time() - task["created_at"], 1),
                    },
                    ensure_ascii=False,
                ),
            ),
        )

    def _alive(self, task):
        if task.get("boot_id") != system_boot_id():
            return False
        return probe_process(task.get("pid"), expected_start_ticks=task.get("start_ticks"))

    def _reconcile(self, con, task):
        if task["status"] in ACTIVE and (
            (task.get("pid") and self._alive(task) is False)
            or (not task.get("pid") and time.time() - task["created_at"] > 30)
        ):
            task.update(
                status="cancelled" if task["status"] == "cancelling" else "failed",
                error="后台进程已退出；已保存的语义文档未被半写，您可以重新执行。",
                finished_at=time.time(),
            )
            self._put(con, task)
            self._event(con, task, task["status"])
        return task

    def list(self):
        if not self.db.exists():
            return []
        with self.connection() as con:
            return [
                self._reconcile(con, json.loads(row[0]))
                for row in con.execute(
                    "SELECT data FROM tasks ORDER BY rowid DESC LIMIT 50"
                ).fetchall()
            ]

    def has_active(self) -> bool:
        """Read-only gate: probing a lost owner must not mutate preparation state."""
        if not self.db.exists():
            return False
        if not self.db.resolve().is_relative_to(self.root):
            raise SemanticsConflict("任务状态目录不能指向工程外。")
        with sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True) as con:
            rows = con.execute("SELECT data FROM tasks").fetchall()
        for row in rows:
            task = json.loads(row[0])
            if task["status"] not in ACTIVE:
                continue
            if task.get("pid"):
                if self._alive(task) is not False:
                    return True
            elif time.time() - task["created_at"] <= 30:
                return True
        return False

    def get(self, task_id: str, cursor: int = 0):
        if not self.db.exists():
            raise ValueError("原语任务不存在。")
        with self.connection() as con:
            row = con.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row is None:
                raise ValueError("原语任务不属于当前工程。")
            task = self._reconcile(con, json.loads(row[0]))
            events = [
                {"cursor": row[0], **json.loads(row[1])}
                for row in con.execute(
                    "SELECT cursor,data FROM events WHERE task=? AND cursor>? ORDER BY cursor LIMIT 100",
                    (task_id, cursor),
                )
            ]
            return {
                "task": task,
                "events": events,
                "cursor": events[-1]["cursor"] if events else cursor,
            }

    def create(self, *, mode: str, request_id: str, expected_revision: str):
        if sys.platform != "linux":
            raise ValueError("原语准备任务需要 Linux/WSL 执行机。")
        if (
            mode not in {"inventory", "discovery"}
            or not isinstance(request_id, str)
            or not 8 <= len(request_id) <= 128
        ):
            raise ValueError("任务类型或 request_id 无效。")
        payload = canonical_digest([mode, expected_revision])
        # Replay is independent of subsequent document edits.
        with self.connection() as con:
            row = con.execute(
                "SELECT payload,data FROM tasks WHERE request_id=?", (request_id,)
            ).fetchone()
            if row:
                if row[0] != payload:
                    raise SemanticsConflict("同一 request_id 不能用于不同任务。")
                return json.loads(row[1])
        with project_activity(self.root, wait_seconds=0.5):
            with self.connection() as con:
                row = con.execute(
                    "SELECT payload,data FROM tasks WHERE request_id=?", (request_id,)
                ).fetchone()
                if row:
                    if row[0] != payload:
                        raise SemanticsConflict("同一 request_id 不能用于不同任务。")
                    return json.loads(row[1])
            config = ConfigLoader.load(str(self.config_path), read_only=True)
            if config.project.language != "c_cpp" or not config.project.semantics_file:
                raise ValueError("请先创建 C/C++ 项目语义文档。")
            if revision(config.project.semantics_file) != expected_revision:
                raise SemanticsConflict("语义文档已变化，请刷新后启动任务。")
            for task in self.list():
                if task["status"] in ACTIVE:
                    raise SemanticsConflict("该工程已有原语任务正在执行。")
            task = {
                "id": uuid.uuid4().hex,
                "mode": mode,
                "status": "queued",
                "created_at": time.time(),
                "document_revision": expected_revision,
                "config_revision": revision(self.config_path),
                "stage": "queued",
            }
            with self.connection() as con:
                con.execute(
                    "INSERT INTO tasks VALUES (?,?,?,?)",
                    (task["id"], request_id, payload, json.dumps(task)),
                )
                self._event(con, task, "queued")
        try:
            with (self.directory / (task["id"] + ".log")).open("ab") as log:
                subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "zscope.orchestration.primitive_tasks",
                        "--config",
                        str(self.config_path),
                        "--task",
                        task["id"],
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                    close_fds=True,
                )
        except OSError as exc:
            self.finish(task["id"], "failed", error=str(exc))
            raise
        return task

    def finish(self, task_id, status, **details):
        with self.connection() as con:
            task = json.loads(
                con.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()[0]
            )
            task.update(status=status, finished_at=time.time(), **details)
            self._put(con, task)
            self._event(con, task, status, details)

    def cancel(self, task_id):
        with self.connection() as con:
            row = con.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not row:
                raise ValueError("原语任务不存在。")
            task = self._reconcile(con, json.loads(row[0]))
            if task["status"] == "publishing":
                raise SemanticsConflict("结果正在原子发布，已不能取消；请等待发布结果。")
            if task["status"] not in ACTIVE:
                return task
            task["status"] = "cancelling"
            self._put(con, task)
        # Shared process identity helpers prevent signalling a reused PID.
        if task.get("pid") and self._alive(task) is True:
            try:
                os.killpg(task["pid"], signal.SIGTERM)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and self._alive(task) is True:
                    time.sleep(0.1)
                if self._alive(task) is True:
                    os.killpg(task["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        return self.get(task_id)["task"]

    def execute(self, task_id):
        last = ["", 0.0]

        def progress(stage, details):
            with self.connection() as con:
                task = json.loads(
                    con.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()[0]
                )
                if task["status"] == "cancelling":
                    raise PreparationCancelled()
                task.update(stage=stage, status="publishing" if stage == "merging" else "running")
                self._put(con, task)
                if stage != last[0] or time.monotonic() - last[1] >= 1:
                    self._event(con, task, stage, details)
                    last[:] = [stage, time.monotonic()]

        def cancelled(_signum, _frame):
            raise PreparationCancelled()

        signal.signal(signal.SIGTERM, cancelled)
        try:
            with project_activity(self.root):
                with self.connection() as con:
                    task = json.loads(
                        con.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()[0]
                    )
                    if task["status"] != "queued":
                        raise PreparationCancelled()
                    task.update(
                        pid=os.getpid(),
                        start_ticks=read_process_start_ticks(os.getpid()),
                        boot_id=system_boot_id(),
                        status="running",
                    )
                    self._put(con, task)
                config = ConfigLoader.load(str(self.config_path), read_only=True)
                if (
                    revision(self.config_path) != task["config_revision"]
                    or revision(config.project.semantics_file) != task["document_revision"]
                ):
                    raise SemanticsConflict("排队期间工程配置或语义文档已变化，请重新执行。")
                result = run_preparation(config, mode=task["mode"], progress=progress)
                result_path = self.directory / (task_id + ".json")
                temporary = result_path.with_suffix(".tmp")
                temporary.write_text(
                    json.dumps(result, ensure_ascii=False, default=str), encoding="utf-8"
                )
                temporary.replace(result_path)
                self.finish(
                    task_id, "completed", result_ref=result_path.relative_to(self.root).as_posix()
                )
        except PreparationCancelled:
            self.finish(task_id, "cancelled")
        except Exception as exc:
            self.finish(task_id, "failed", error=str(exc))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--task", required=True)
    args = parser.parse_args()
    PrimitiveTasks(args.config).execute(args.task)
