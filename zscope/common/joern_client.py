"""
Joern CPG server client - manages joern-server subprocess and executes CPGQL queries.
"""

import atexit
import json
import logging
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

logger = logging.getLogger(__name__)

DEFAULT_QUERY_TIMEOUT_SECONDS = 300.0
DEFAULT_QUERY_MAX_ATTEMPTS = 2
CPG_IMPORT_QUERY_TIMEOUT_SECONDS = 3600.0


def _scala_string(value: str) -> str:
    """Encode one ordinary Scala string literal, including its quotes.

    JSON's quote, backslash, control-character and Unicode escapes are valid
    in ordinary Scala strings. Never use interpolation or triple quotes here.
    """
    return json.dumps(str(value), ensure_ascii=True)


class JoernQueryError(RuntimeError):
    """Raised when a Joern fact query failed or returned an invalid payload."""


class JoernClient:
    """Client for Joern CPG server via cpgqls-client WebSocket."""

    def __init__(
        self,
        joern_path: str = "joern",
        host: str = "127.0.0.1",
        port: int = 8080,
        heap_size: str = "8g",
        language: str = "c",
        query_timeout_seconds: float = DEFAULT_QUERY_TIMEOUT_SECONDS,
        query_max_attempts: int = DEFAULT_QUERY_MAX_ATTEMPTS,
    ):
        self.joern_path = joern_path
        self.host = host
        self.port = port
        self.heap_size = heap_size
        self.language = self._normalize_language(language)
        self.query_timeout_seconds = float(query_timeout_seconds)
        self.query_max_attempts = int(query_max_attempts)
        if self.query_timeout_seconds <= 0:
            raise ValueError("query_timeout_seconds must be positive")
        if self.query_max_attempts <= 0:
            raise ValueError("query_max_attempts must be positive")

        self._server_process: Optional[subprocess.Popen] = None
        self._cli_mode = False
        self._cpg_path: Optional[str] = None
        self._cpg_loaded = False
        self._cpg_build_status = "idle"  # idle | building | ready | error
        self._cpg_build_error: Optional[str] = None
        self._cpg_lock = threading.Lock()
        self._cpg_build_thread: Optional[threading.Thread] = None
        self._cleanup_registered = False
        self._query_loop_local = threading.local()
        self._query_event_loops: List[Any] = []
        self._query_event_loops_lock = threading.Lock()

    def start_server(self) -> bool:
        """Start joern-server subprocess, falling back to CLI project mode."""
        if self._server_process and self._server_process.poll() is None:
            return True
        if self._cli_mode:
            return True
        if str(self.joern_path).lower().endswith(".bat"):
            logger.info("Using Joern CLI mode for launcher: %s", self.joern_path)
            self._cli_mode = True
            return True
        try:
            cmd = [
                self.joern_path,
                "--server",
                "--server-host",
                self.host,
                "--server-port",
                str(self.port),
                f"-J-Xmx{self.heap_size}",
            ]
            logger.info("Starting Joern server: %s", " ".join(cmd))
            self._server_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            # Wait for server to be ready
            if not self._wait_for_server(timeout=45):
                stderr_out = b""
                if (
                    self._server_process
                    and self._server_process.poll() is not None
                    and self._server_process.stderr
                ):
                    stderr_out = self._server_process.stderr.read()
                logger.warning(
                    "Joern server did not become ready; falling back to CLI mode. stderr: %s",
                    stderr_out.decode("utf-8", errors="ignore"),
                )
                self.stop_server()
                self._cli_mode = True
                return True
            logger.info("Joern server started on %s:%d", self.host, self.port)
            self._register_cleanup()
            return True
        except Exception as e:
            logger.error("Failed to start Joern server: %s", e)
            return False

    def _register_cleanup(self):
        """注册退出清理，确保进程退出时关闭 Joern server。"""
        if self._cleanup_registered:
            return
        self._cleanup_registered = True
        atexit.register(self.stop_server)

        # signal.signal() 只能在主线程调用，非主线程跳过（atexit 仍生效）
        if threading.current_thread() is not threading.main_thread():
            return

        def _sigterm_handler(signum, frame):
            self.stop_server()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.raise_signal(signal.SIGTERM)

        signal.signal(signal.SIGTERM, _sigterm_handler)

    def _wait_for_server(self, timeout: int = 120) -> bool:
        """Wait for Joern server to accept connections."""
        import socket

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._server_process and self._server_process.poll() is not None:
                return False
            try:
                with socket.create_connection((self.host, self.port), timeout=2):
                    return True
            except (ConnectionRefusedError, OSError):
                time.sleep(1)
        return False

    def stop_server(self):
        """Stop joern-server subprocess."""
        if self._server_process:
            self._server_process.terminate()
            try:
                self._server_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._server_process.kill()
            self._server_process = None
        with self._query_event_loops_lock:
            loops = list(self._query_event_loops)
            self._query_event_loops.clear()
        for loop in loops:
            if not loop.is_running() and not loop.is_closed():
                loop.close()
        self._cpg_loaded = False

    def _get_query_event_loop(self) -> Any:
        import asyncio

        loop = getattr(self._query_loop_local, "loop", None)
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            self._query_loop_local.loop = loop
            with self._query_event_loops_lock:
                self._query_event_loops.append(loop)
        return loop

    def _wait_for_cpg_ready(self, timeout: int = 7200, poll_interval: int = 10) -> bool:
        """轮询验证 CPG 是否真正加载完成。importCode 可能异步返回，需要确认 CPG 可查询。"""
        import time

        deadline = time.time() + timeout
        print("  [Joern] Waiting for CPG build to complete...", flush=True)
        while time.time() < deadline:
            try:
                result = self.query(
                    "cpg.method.size",
                    timeout_seconds=min(self.query_timeout_seconds, 30.0),
                    max_attempts=1,
                )
                if isinstance(result, (int, str)):
                    count = (
                        int(result)
                        if isinstance(result, str) and result.strip().isdigit()
                        else result
                    )
                    if isinstance(count, int) and count > 0:
                        print(f"  [Joern] CPG ready, {count} methods indexed.", flush=True)
                        return True
            except Exception:
                pass
            time.sleep(poll_interval)
        logger.error("CPG build verification timed out after %ds", timeout)
        return False

    @staticmethod
    def _normalize_language(language: Optional[str]) -> str:
        text = str(language or "c").strip().lower().replace("-", "_")
        aliases = {
            "auto": "c",
            "c_cpp": "c",
            "cpp": "c",
            "c++": "c",
            "java_src": "java",
            "javasrc": "java",
        }
        normalized = aliases.get(text, text or "c")
        if normalized not in {"c", "java"}:
            raise ValueError(f"Unsupported Joern language: {language!r}")
        return normalized

    def _build_import_code_query(
        self,
        source_path_escaped: str,
        compile_commands_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> str:
        """Build importCode CPGQL query, optionally with compile_commands.json."""
        normalized_language = self._normalize_language(language or self.language)
        if normalized_language == "java":
            return f'importCode.javasrc(inputPath="{source_path_escaped}")'
        if compile_commands_path:
            cc_escaped = compile_commands_path.replace("\\", "\\\\")
            return (
                f'importCode.c(inputPath="{source_path_escaped}", args=List('
                f'"--compilation-database", "{cc_escaped}"))'
            )
        # We can also force it to use C to prevent falling back to python
        return f'importCode.c(inputPath="{source_path_escaped}")'

    def import_cpg(
        self,
        source_path: str,
        project_root: Optional[str] = None,
        compile_commands_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> bool:
        """Build CPG from source directory or load existing cpg.bin."""
        normalized_language = self._normalize_language(language or self.language)
        if self._cli_mode:
            return self._import_cpg_via_cli(
                source_path,
                project_root,
                compile_commands_path,
                language=normalized_language,
            )

        import os

        logger.info("Importing CPG for source: %s", source_path)

        cpg_bin = os.path.join(source_path, "cpg.bin")
        if project_root and not os.path.exists(cpg_bin):
            alt_cpg_bin = os.path.join(project_root, "cpg.bin")
            if os.path.exists(alt_cpg_bin):
                cpg_bin = alt_cpg_bin

        if os.path.exists(cpg_bin):
            cpg_bin_escaped = cpg_bin.replace("\\", "\\\\")
            print(f"  [Joern] Found existing CPG, importing {cpg_bin}...", flush=True)
            result = self.query(
                f'importCpg("{cpg_bin_escaped}")',
                timeout_seconds=CPG_IMPORT_QUERY_TIMEOUT_SECONDS,
                max_attempts=1,
            )
        else:
            source_path_escaped = source_path.replace("\\", "\\\\")
            print(f"  [Joern] Building CPG for {source_path}...", flush=True)
            result = self.query(
                self._build_import_code_query(
                    source_path_escaped,
                    compile_commands_path,
                    language=normalized_language,
                ),
                timeout_seconds=CPG_IMPORT_QUERY_TIMEOUT_SECONDS,
                max_attempts=1,
            )
            if result is not None:
                # importCode 可能异步返回项目引用，需要轮询确认 CPG 真正加载完成
                if not self._wait_for_cpg_ready():
                    logger.error("CPG build timed out or failed verification")
                    with self._cpg_lock:
                        self._cpg_build_status = "error"
                        self._cpg_build_error = "CPG build verification failed"
                    return False
        if result is not None:
            self._cpg_loaded = True
            with self._cpg_lock:
                self._cpg_build_status = "ready"
            logger.info("CPG import completed")
            print("  [Joern] CPG import completed.", flush=True)
            return True
        logger.error("CPG import failed")
        with self._cpg_lock:
            self._cpg_build_status = "error"
            self._cpg_build_error = "CPG import returned None"
        return False

    def _import_cpg_via_cli(
        self,
        source_path: str,
        project_root: Optional[str] = None,
        compile_commands_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> bool:
        """Build or reuse a CPG for Joern CLI script execution."""
        import os

        normalized_language = self._normalize_language(language or self.language)

        logger.info("Importing CPG via Joern CLI for source: %s", source_path)
        source = Path(source_path).resolve()
        root = (
            Path(project_root).resolve()
            if project_root
            else (source if source.is_dir() else source.parent)
        )

        candidates = [
            source / "cpg.bin",
            root / "cpg.bin",
            root / ".zscope_joern" / "cpg.bin",
        ]
        for candidate in candidates:
            if candidate.exists():
                self._cpg_path = str(candidate)
                self._cpg_loaded = True
                with self._cpg_lock:
                    self._cpg_build_status = "ready"
                    self._cpg_build_error = None
                return True

        out_dir = root / ".zscope_joern"
        out_dir.mkdir(parents=True, exist_ok=True)
        cpg_path = out_dir / "cpg.bin"
        parse_cmd = [
            self._joern_parse_path(),
            str(source),
            "-o",
            str(cpg_path),
        ]
        parse_cmd.extend(["--language", "JAVASRC" if normalized_language == "java" else normalized_language])
        if compile_commands_path and normalized_language == "c":
            parse_cmd.extend(
                [
                    "--frontend-args",
                    "--compilation-database",
                    str(compile_commands_path),
                ]
            )
        try:
            proc = subprocess.run(
                parse_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=7200,
            )
        except Exception as exc:
            with self._cpg_lock:
                self._cpg_build_status = "error"
                self._cpg_build_error = str(exc)
            logger.error("Joern CLI parse failed: %s", exc)
            return False
        if proc.returncode != 0 or not os.path.exists(cpg_path):
            err = (proc.stderr or proc.stdout or "Joern parse failed").strip()
            with self._cpg_lock:
                self._cpg_build_status = "error"
                self._cpg_build_error = err
            logger.error("Joern CLI parse failed: %s", err)
            return False
        self._cpg_path = str(cpg_path)
        self._cpg_loaded = True
        with self._cpg_lock:
            self._cpg_build_status = "ready"
            self._cpg_build_error = None
        logger.info("Joern CLI CPG ready at %s", cpg_path)
        return True

    def import_cpg_async(
        self,
        source_path: str,
        project_root: Optional[str] = None,
        compile_commands_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> None:
        """Start CPG build in background thread."""
        normalized_language = self._normalize_language(language or self.language)
        with self._cpg_lock:
            if self._cpg_build_status == "building":
                logger.warning("CPG build already in progress")
                return
            self._cpg_build_status = "building"
            self._cpg_build_error = None

        def _build():
            try:
                if self._cli_mode:
                    self._import_cpg_via_cli(
                        source_path,
                        project_root,
                        compile_commands_path,
                        language=normalized_language,
                    )
                    return
                import os

                cpg_bin = os.path.join(source_path, "cpg.bin")
                if project_root and not os.path.exists(cpg_bin):
                    alt_cpg_bin = os.path.join(project_root, "cpg.bin")
                    if os.path.exists(alt_cpg_bin):
                        cpg_bin = alt_cpg_bin

                if os.path.exists(cpg_bin):
                    cpg_bin_escaped = cpg_bin.replace("\\", "\\\\")
                    result = self.query(
                        f'importCpg("{cpg_bin_escaped}")',
                        timeout_seconds=CPG_IMPORT_QUERY_TIMEOUT_SECONDS,
                        max_attempts=1,
                    )
                else:
                    source_path_escaped = source_path.replace("\\", "\\\\")
                    result = self.query(
                        self._build_import_code_query(
                            source_path_escaped,
                            compile_commands_path,
                            language=normalized_language,
                        ),
                        timeout_seconds=CPG_IMPORT_QUERY_TIMEOUT_SECONDS,
                        max_attempts=1,
                    )
                    if result is not None and not self._wait_for_cpg_ready():
                        result = None
                with self._cpg_lock:
                    if result is not None:
                        self._cpg_loaded = True
                        self._cpg_build_status = "ready"
                    else:
                        self._cpg_build_status = "error"
                        self._cpg_build_error = "CPG import returned None"
            except Exception as e:
                with self._cpg_lock:
                    self._cpg_build_status = "error"
                    self._cpg_build_error = str(e)

        self._cpg_build_thread = threading.Thread(target=_build, daemon=True)
        self._cpg_build_thread.start()

    def wait_for_cpg(self, timeout: Optional[int] = None) -> bool:
        """Block until CPG is ready. Returns True if ready."""
        if self._cpg_build_thread:
            self._cpg_build_thread.join(timeout=timeout)
        return self.cpg_status == "ready"

    @staticmethod
    def _parse_server_stdout(stdout: str) -> Any:
        """Normalize values printed by the Joern server REPL."""
        import ast
        import re

        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        clean_stdout = ansi_escape.sub("", str(stdout or "")).strip()

        string_match = re.search(
            r"val\s+res\d+\s*:\s*String\s*=\s*(.*)",
            clean_stdout,
            re.DOTALL,
        )
        if string_match:
            scala_literal = string_match.group(1).strip()
            try:
                if scala_literal.startswith('"""') and scala_literal.endswith('"""'):
                    json_text = scala_literal[3:-3]
                else:
                    json_text = ast.literal_eval(scala_literal)
                return json.loads(json_text)
            except (SyntaxError, ValueError, json.JSONDecodeError):
                pass

        scalar_match = re.search(
            r"val\s+res\d+\s*:\s*(Int|Long|Double|Float|Boolean)\s*=\s*([^\r\n]+)",
            clean_stdout,
        )
        if scalar_match:
            scalar_type, raw_value = scalar_match.groups()
            raw_value = raw_value.strip()
            if scalar_type == "Boolean":
                if raw_value == "true":
                    return True
                if raw_value == "false":
                    return False
            elif scalar_type in {"Int", "Long"}:
                try:
                    return int(raw_value.rstrip("Ll"))
                except ValueError:
                    pass
            else:
                try:
                    return float(raw_value.rstrip("FfDd"))
                except ValueError:
                    pass

        json_match = re.search(r"([\[\{].*[\]\}])", clean_stdout, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        return clean_stdout

    @property
    def cpg_status(self) -> str:
        with self._cpg_lock:
            return self._cpg_build_status

    @property
    def cpg_error(self) -> Optional[str]:
        with self._cpg_lock:
            return self._cpg_build_error

    def query(
        self,
        cpgql: str,
        timeout_seconds: Optional[float] = None,
        max_attempts: Optional[int] = None,
    ) -> Any:
        """Execute a bounded CPGQL query via cpgqls-client."""
        query_timeout = float(
            self.query_timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        query_attempts = int(self.query_max_attempts if max_attempts is None else max_attempts)
        if query_timeout <= 0:
            raise ValueError("timeout_seconds must be positive")
        if query_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self._cli_mode:
            return self._query_via_cli(cpgql, timeout_seconds=query_timeout)
        try:
            from cpgqls_client import CPGQLSClient  # type: ignore[import-untyped]

            import asyncio

            # Workaround for cpgqls-client concurrent UUID broadcast bug
            if not hasattr(CPGQLSClient, "_zscope_patched"):
                original_send_query = getattr(CPGQLSClient, "_send_query", None)
                if original_send_query:

                    async def patched_send_query(self, query_str):
                        timeout = float(
                            getattr(
                                self,
                                "_zscope_query_timeout_seconds",
                                DEFAULT_QUERY_TIMEOUT_SECONDS,
                            )
                        )
                        endpoint = self.connect_endpoint()
                        async with self._transport.connect(endpoint) as ws_conn:
                            connected_msg = await asyncio.wait_for(
                                ws_conn.recv(), timeout=min(timeout, 30.0)
                            )
                            if connected_msg != self.CPGQLS_MSG_CONNECTED:
                                raise Exception("Received unexpected first message")
                            endpoint = self.post_query_endpoint()
                            post_res = self._transport.post(
                                endpoint, json={"query": query_str}, auth=self._auth_creds
                            )
                            if post_res.status_code != 200:
                                raise Exception(f"HTTP Post failed: {post_res.status_code}")

                            target_uuid = post_res.json()["uuid"]
                            while True:
                                msg = await asyncio.wait_for(ws_conn.recv(), timeout=timeout)
                                if msg == target_uuid:
                                    break

                            endpoint = self.get_result_endpoint(target_uuid)
                            get_res = self._transport.get(endpoint, auth=self._auth_creds)
                            if get_res.status_code != 200:
                                raise Exception(f"HTTP Get failed: {get_res.status_code}")
                            return get_res.json()

                    CPGQLSClient._send_query = patched_send_query
                    CPGQLSClient._zscope_patched = True

            import os

            for attempt in range(query_attempts):
                try:
                    # Temporarily bypass any global proxies that might hijack local WS connections
                    old_http = os.environ.get("HTTP_PROXY")
                    old_https = os.environ.get("HTTPS_PROXY")
                    old_no = os.environ.get("NO_PROXY")
                    os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"

                    try:
                        # cpgqls_client adds "ws://" internally. Do not pass it here or it creates ws://ws://...
                        client = CPGQLSClient(
                            f"{self.host}:{self.port}",
                            event_loop=self._get_query_event_loop(),
                        )
                        client._zscope_query_timeout_seconds = query_timeout
                        result = client.execute(cpgql)
                    finally:
                        if old_http is not None:
                            os.environ["HTTP_PROXY"] = old_http
                        if old_https is not None:
                            os.environ["HTTPS_PROXY"] = old_https
                        if old_no is not None:
                            os.environ["NO_PROXY"] = old_no
                        elif "NO_PROXY" in os.environ:
                            del os.environ["NO_PROXY"]

                    if isinstance(result, dict) and "stdout" in result:
                        return self._parse_server_stdout(result["stdout"])
                    return result
                except Exception as e:
                    retryable = (
                        "handshake" in str(e)
                        or "timeout" in str(e).lower()
                        or isinstance(e, (asyncio.TimeoutError, TimeoutError, ConnectionError))
                    )
                    if retryable:
                        if attempt + 1 < query_attempts:
                            logger.warning(
                                "Joern query attempt %d/%d failed: %s. Retrying...",
                                attempt + 1,
                                query_attempts,
                                type(e).__name__,
                            )
                            time.sleep(5)
                            continue
                    raise e

        except ImportError:
            return self._query_via_cli(cpgql, timeout_seconds=query_timeout)
        except Exception as e:
            logger.error("Joern query failed: %s", e)
            return None

    def _query_via_cli(self, cpgql: str, timeout_seconds: float = 600.0) -> Any:
        """Fallback: execute query via joern CLI."""
        script_path = None
        try:
            script_path = self._write_cli_query_script(cpgql, self._cpg_path)
            cmd = [self.joern_path, "--nocolors", "--script", script_path]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
            if proc.returncode != 0:
                logger.error("Joern CLI error: %s", proc.stderr)
                return None
            return self._parse_cli_query_stdout(proc.stdout)
        except Exception as e:
            logger.error("Joern CLI query failed: %s", e)
            return None
        finally:
            if script_path:
                try:
                    Path(script_path).unlink(missing_ok=True)
                except Exception:
                    pass

    def _joern_parse_path(self) -> str:
        raw = str(self.joern_path)
        lower = raw.lower()
        if lower.endswith("joern.bat"):
            return raw[: -len("joern.bat")] + "joern-parse.bat"
        if lower.endswith("joern"):
            prefix = raw[: -len("joern")]
            return prefix + "joern-parse" if prefix else "joern-parse"
        return "joern-parse"

    def _write_cli_query_script(self, cpgql: str, cpg_path: Optional[str] = None) -> str:
        prelude = ""
        if cpg_path:
            escaped = str(Path(cpg_path).resolve()).replace("\\", "\\\\").replace('"', '\\"')
            prelude = f'importCpg("{escaped}", "zscope_cli", enhance=true)\n'
        body = prelude + (
            "val __zscope_result = {\n"
            f"{cpgql}\n"
            "}\n"
            'println("__ZSCOPE_JSON_BEGIN__")\n'
            "println(__zscope_result)\n"
            'println("__ZSCOPE_JSON_END__")\n'
        )
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".sc", prefix="zscope_joern_", delete=False, encoding="utf-8"
        )
        try:
            handle.write(body)
            return handle.name
        finally:
            handle.close()

    @staticmethod
    def _parse_cli_query_stdout(stdout: str) -> Any:
        import re

        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        clean = ansi_escape.sub("", stdout or "")
        marker = re.search(
            r"__ZSCOPE_JSON_BEGIN__\s*(.*?)\s*__ZSCOPE_JSON_END__",
            clean,
            re.DOTALL,
        )
        text = marker.group(1).strip() if marker else clean.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    # ── Convenience methods ──

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        """Get method node by exact name."""
        result = self.query(
            f'cpg.method.name({_scala_string(name)}).map(m => Map('
            f'"name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1), '
            f'"lineNumberEnd" -> m.lineNumberEnd.getOrElse(-1), '
            f'"signature" -> m.signature'
            f")).l.toJson"
        )
        rows = self._require_list_result(result, "get_method")
        if rows:
            return cast(Dict[str, Any], rows[0])
        return None

    def get_method_callers(
        self,
        name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        """Get functions that call the given function."""
        method_query = f'cpg.method.name({_scala_string(name)})'
        clean_file = str(callee_file or "").replace("\\", "/").strip()
        if clean_file:
            method_query += (
                f'.filter(m => m.filename == {_scala_string(clean_file)} || '
                f'm.filename.endsWith({_scala_string("/" + clean_file)}) || '
                f'{_scala_string(clean_file)}.endsWith("/" + m.filename))'
            )
        result = self.query(
            f"{method_query}.callIn.method.distinct"
            f'.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1)))'
            f".take({int(limit)}).l.toJson"
        )
        return self._require_list_result(result, "get_method_callers")

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Get functions called by the given function."""
        result = self.query(
            f'cpg.method.name({_scala_string(name)}).callee.distinct'
            f'.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1)))'
            f".take({int(limit)}).l.toJson"
        )
        return self._require_list_result(result, "get_method_callees")

    def get_type_decl(self, name: str) -> Optional[Dict[str, Any]]:
        """Get type declaration (struct/union/enum) by name."""
        result = self.query(
            f'cpg.typeDecl.name({_scala_string(name)}).map(t => Map('
            f'"name" -> t.name, "filename" -> t.filename, '
            f'"lineNumber" -> t.lineNumber.getOrElse(-1)'
            f")).l.toJson"
        )
        rows = self._require_list_result(result, "get_type_decl")
        if rows:
            return cast(Dict[str, Any], rows[0])
        return None

    def get_type_decls(self, name: str) -> List[Dict[str, Any]]:
        """Get every same-name type declaration with its source definition."""
        result = self.query(
            f'cpg.typeDecl.name({_scala_string(name)}).map(t => Map('
            f'"name" -> t.name, "filename" -> t.filename, '
            f'"lineNumber" -> t.lineNumber.getOrElse(-1), '
            f'"lineNumberEnd" -> t.lineNumberEnd.getOrElse(-1), '
            f'"full_definition" -> t.code'
            f")).l.toJson"
        )
        return self._require_list_result(result, "get_type_decls")

    def get_type_members(self, name: str) -> List[Dict[str, Any]]:
        """Get members of a type declaration."""
        result = self.query(
            f'cpg.typeDecl.name({_scala_string(name)}).member'
            f'.map(m => Map("name" -> m.name, "typeFullName" -> m.typeFullName))'
            f".l.toJson"
        )
        return self._require_list_result(result, "get_type_members")

    def get_function_type_references(
        self,
        name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Return direct signature/local type facts exposed by the Joern CPG."""
        clean_file = str(file_path or "").replace("\\", "/")
        method = f'cpg.method.nameExact({_scala_string(name)})'
        if clean_file:
            method += f'.filter(m => m.filename.replace("\\\\", "/").endsWith({_scala_string(clean_file)}))'
        result = self.query(
            method
            + ".flatMap(m => "
            + 'm.methodReturn.map(v => Map("typeFullName" -> v.typeFullName, '
            + '"lineNumber" -> v.lineNumber.getOrElse(m.lineNumber.getOrElse(-1)), '
            + '"referenceKind" -> "return")) ++ '
            + 'm.parameter.map(v => Map("typeFullName" -> v.typeFullName, '
            + '"lineNumber" -> v.lineNumber.getOrElse(m.lineNumber.getOrElse(-1)), '
            + '"referenceKind" -> "parameter")) ++ '
            + 'm.local.map(v => Map("typeFullName" -> v.typeFullName, '
            + '"lineNumber" -> v.lineNumber.getOrElse(m.lineNumber.getOrElse(-1)), '
            + '"referenceKind" -> "local"))'
            + ").l.toJson"
        )
        return self._require_list_result(result, "get_function_type_references")

    def find_methods(self, pattern: str, limit: int = 50) -> List[str]:
        """Find method names matching a regex pattern."""
        result = self.query(f'cpg.method.name({_scala_string(pattern)}).name.distinct.take({int(limit)}).l.toJson')
        rows = self._require_list_result(result, "find_methods")
        return [str(item) for item in rows]

    def get_data_flow_to_sink(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        """Trace data flow from source parameter to sink calls."""
        result = self.query(
            f'def src = cpg.method.name({_scala_string(source_func)}).parameter.name({_scala_string(source_param)})\n'
            f'def snk = cpg.call.name({_scala_string(sink_pattern)}).argument\n'
            f"sink(snk).reachableByFlows(source(src))"
            f'.map(f => Map("path" -> f.elements.map(e => '
            f'Map("code" -> e.code, "lineNumber" -> e.lineNumber.getOrElse(-1), '
            f'"filename" -> e.file.name.headOption.getOrElse(""))).l'
            f")).l.toJson"
        )
        return self._require_list_result(result, "get_data_flow_to_sink")

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """Find assignments/references to function as pointer."""
        result = self.query(
            f'cpg.identifier.name({_scala_string(func_name)}).inAssignment'
            f'.map(a => Map("code" -> a.code, '
            f'"filename" -> a.file.name.headOption.getOrElse(""), '
            f'"lineNumber" -> a.lineNumber.getOrElse(-1)))'
            f".l.toJson"
        )
        return self._require_list_result(result, "find_function_pointers")

    @staticmethod
    def _require_list_result(result: Any, operation: str) -> List[Any]:
        """Distinguish a valid empty fact set from a failed Joern query."""

        if isinstance(result, list):
            return result
        result_type = type(result).__name__
        raise JoernQueryError(f"Joern {operation} query returned {result_type}, expected list")
