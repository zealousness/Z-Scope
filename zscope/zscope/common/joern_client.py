"""
Joern CPG server client - manages joern-server subprocess and executes CPGQL queries.
"""

import atexit
import json
import logging
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class JoernClient:
    """Client for Joern CPG server via cpgqls-client WebSocket."""

    def __init__(
        self,
        joern_path: str = "joern",
        host: str = "127.0.0.1",
        port: int = 8080,
        heap_size: str = "8g",

    ):
        self.joern_path = joern_path
        self.host = host
        self.port = port
        self.heap_size = heap_size

        self._server_process: Optional[subprocess.Popen] = None
        self._cpg_loaded = False
        self._cpg_build_status = "idle"  # idle | building | ready | error
        self._cpg_build_error: Optional[str] = None
        self._cpg_lock = threading.Lock()
        self._cpg_build_thread: Optional[threading.Thread] = None
        self._cleanup_registered = False

    def start_server(self) -> bool:
        """Start joern-server subprocess."""
        if self._server_process and self._server_process.poll() is None:
            return True
        try:
            cmd = [
                self.joern_path, "--server",
                "--server-host", self.host,
                "--server-port", str(self.port),
                f"-J-Xmx{self.heap_size}",
            ]
            logger.info("Starting Joern server: %s", " ".join(cmd))
            self._server_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            # Wait for server to be ready
            if not self._wait_for_server():
                stderr_out = b""
                if self._server_process and self._server_process.poll() is not None:
                    stderr_out = self._server_process.stderr.read()
                logger.error(f"Joern server failed to start. stderr: {stderr_out.decode('utf-8', errors='ignore')}")
                return False
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
        self._cpg_loaded = False

    def _build_import_code_query(self, source_path_escaped: str, compile_commands_path: Optional[str] = None) -> str:
        """Build importCode CPGQL query, optionally with compile_commands.json."""
        if compile_commands_path:
            cc_escaped = compile_commands_path.replace("\\", "\\\\")
            return (
                f'importCode("{source_path_escaped}", args=List('
                f'"--compilation-database", "{cc_escaped}"))'
            )
        return f'importCode("{source_path_escaped}")'

    def import_cpg(
        self,
        source_path: str,
        project_root: Optional[str] = None,
        compile_commands_path: Optional[str] = None,
    ) -> bool:
        """Build CPG from source directory or load existing cpg.bin."""
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
            result = self.query(f'importCpg("{cpg_bin_escaped}")')
        else:
            source_path_escaped = source_path.replace("\\", "\\\\")
            print(f"  [Joern] Building CPG for {source_path}...", flush=True)
            result = self.query(self._build_import_code_query(source_path_escaped, compile_commands_path))
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

    def import_cpg_async(
        self,
        source_path: str,
        project_root: Optional[str] = None,
        compile_commands_path: Optional[str] = None,
    ) -> None:
        """Start CPG build in background thread."""
        with self._cpg_lock:
            if self._cpg_build_status == "building":
                logger.warning("CPG build already in progress")
                return
            self._cpg_build_status = "building"
            self._cpg_build_error = None

        def _build():
            try:
                import os
                cpg_bin = os.path.join(source_path, "cpg.bin")
                if project_root and not os.path.exists(cpg_bin):
                    alt_cpg_bin = os.path.join(project_root, "cpg.bin")
                    if os.path.exists(alt_cpg_bin):
                        cpg_bin = alt_cpg_bin

                if os.path.exists(cpg_bin):
                    cpg_bin_escaped = cpg_bin.replace("\\", "\\\\")
                    result = self.query(f'importCpg("{cpg_bin_escaped}")')
                else:
                    source_path_escaped = source_path.replace("\\", "\\\\")
                    result = self.query(self._build_import_code_query(source_path_escaped, compile_commands_path))
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

    @property
    def cpg_status(self) -> str:
        with self._cpg_lock:
            return self._cpg_build_status

    @property
    def cpg_error(self) -> Optional[str]:
        with self._cpg_lock:
            return self._cpg_build_error

    def query(self, cpgql: str) -> Any:
        """Execute a CPGQL query via cpgqls-client."""
        try:
            from cpgqls_client import CPGQLSClient
            
            # Workaround for cpgqls-client concurrent UUID broadcast bug
            if not hasattr(CPGQLSClient, '_zscope_patched'):
                import asyncio
                original_send_query = getattr(CPGQLSClient, '_send_query', None)
                if original_send_query:
                    async def patched_send_query(self, query_str):
                        endpoint = self.connect_endpoint()
                        async with self._transport.connect(endpoint) as ws_conn:
                            connected_msg = await ws_conn.recv()
                            if connected_msg != self.CPGQLS_MSG_CONNECTED:
                                raise Exception("Received unexpected first message")
                            endpoint = self.post_query_endpoint()
                            post_res = self._transport.post(endpoint, json={"query": query_str}, auth=self._auth_creds)
                            if post_res.status_code != 200:
                                raise Exception(f"HTTP Post failed: {post_res.status_code}")
                                
                            target_uuid = post_res.json()["uuid"]
                            while True:
                                msg = await asyncio.wait_for(ws_conn.recv(), timeout=3600)
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
            
            for attempt in range(30):
                try:
                    # Temporarily bypass any global proxies that might hijack local WS connections
                    old_http = os.environ.get("HTTP_PROXY")
                    old_https = os.environ.get("HTTPS_PROXY")
                    old_no = os.environ.get("NO_PROXY")
                    os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"
                    
                    try:
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            
                        # cpgqls_client adds "ws://" internally. Do not pass it here or it creates ws://ws://...
                        client = CPGQLSClient(f"{self.host}:{self.port}", event_loop=loop)
                        result = client.execute(cpgql)
                    finally:
                        if old_http is not None: os.environ["HTTP_PROXY"] = old_http
                        if old_https is not None: os.environ["HTTPS_PROXY"] = old_https
                        if old_no is not None: os.environ["NO_PROXY"] = old_no
                        elif "NO_PROXY" in os.environ: del os.environ["NO_PROXY"]
                        
                    if isinstance(result, dict) and "stdout" in result:
                        stdout = result["stdout"]
                        import re
                        import ast
                        # Strip ANSI color codes Joern might output
                        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                        clean_stdout = ansi_escape.sub('', stdout).strip()

                        # Check if it's a Scala string assignment (e.g. val res1: String = "[...]")
                        match = re.search(r'val\s+res\d+\s*:\s*String\s*=\s*(.*)', clean_stdout, re.DOTALL)
                        if match:
                            scala_literal = match.group(1).strip()
                            try:
                                # ast.literal_eval handles both quotes "" and triple quotes """""" escaping
                                if scala_literal.startswith('"""') and scala_literal.endswith('"""'):
                                    json_str = scala_literal[3:-3]
                                else:
                                    json_str = ast.literal_eval(scala_literal)
                                return json.loads(json_str)
                            except (SyntaxError, ValueError, json.JSONDecodeError):
                                pass
                                
                        # Fallback for plain unquoted JSON array/object inside stdout
                        match_json = re.search(r'([\[\{].*[\]\}])', clean_stdout, re.DOTALL)
                        if match_json:
                            try:
                                return json.loads(match_json.group(1))
                            except json.JSONDecodeError:
                                pass
                                
                        return clean_stdout
                    return result
                except Exception as e:
                    if "handshake" in str(e) or "timeout" in str(e).lower() or isinstance(e, ConnectionError):
                        if attempt < 29:
                            logger.warning(f"Joern query attempt {attempt+1} failed: {e}. Retrying...")
                            time.sleep(5)
                            continue
                    raise e
                    
        except ImportError:
            return self._query_via_cli(cpgql)
        except Exception as e:
            logger.error("Joern query failed: %s", e)
            return None

    def _query_via_cli(self, cpgql: str) -> Any:
        """Fallback: execute query via joern CLI."""
        try:
            cmd = [self.joern_path, "--script", "/dev/stdin"]
            proc = subprocess.run(
                cmd, input=cpgql, capture_output=True, text=True, timeout=300
            )
            if proc.returncode != 0:
                logger.error("Joern CLI error: %s", proc.stderr)
                return None
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                return proc.stdout.strip()
        except Exception as e:
            logger.error("Joern CLI query failed: %s", e)
            return None

    # ── Convenience methods ──

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        """Get method node by exact name."""
        result = self.query(
            f'cpg.method.name("{name}").map(m => Map('
            f'"name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1), '
            f'"lineNumberEnd" -> m.lineNumberEnd.getOrElse(-1), '
            f'"signature" -> m.signature'
            f')).l.toJson'
        )
        if isinstance(result, list) and result:
            return result[0]
        return None

    def get_method_callers(self, name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get functions that call the given function."""
        result = self.query(
            f'cpg.method.name("{name}").callIn.method.distinct'
            f'.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1)))'
            f'.take({limit}).l.toJson'
        )
        return result if isinstance(result, list) else []

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Get functions called by the given function."""
        result = self.query(
            f'cpg.method.name("{name}").callee.distinct'
            f'.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1)))'
            f'.take({limit}).l.toJson'
        )
        return result if isinstance(result, list) else []

    def get_type_decl(self, name: str) -> Optional[Dict[str, Any]]:
        """Get type declaration (struct/union/enum) by name."""
        result = self.query(
            f'cpg.typeDecl.name("{name}").map(t => Map('
            f'"name" -> t.name, "filename" -> t.filename, '
            f'"lineNumber" -> t.lineNumber.getOrElse(-1)'
            f')).l.toJson'
        )
        if isinstance(result, list) and result:
            return result[0]
        return None

    def get_type_members(self, name: str) -> List[Dict[str, Any]]:
        """Get members of a type declaration."""
        result = self.query(
            f'cpg.typeDecl.name("{name}").member'
            f'.map(m => Map("name" -> m.name, "typeFullName" -> m.typeFullName))'
            f'.l.toJson'
        )
        return result if isinstance(result, list) else []

    def find_methods(self, pattern: str, limit: int = 50) -> List[str]:
        """Find method names matching a regex pattern."""
        result = self.query(
            f'cpg.method.name("{pattern}").name.distinct.take({limit}).l.toJson'
        )
        return result if isinstance(result, list) else []

    def get_data_flow_to_sink(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        """Trace data flow from source parameter to sink calls."""
        result = self.query(
            f'def src = cpg.method.name("{source_func}").parameter.name("{source_param}")\n'
            f'def snk = cpg.call.name("{sink_pattern}").argument\n'
            f'sink(snk).reachableByFlows(source(src))'
            f'.map(f => Map("path" -> f.elements.map(e => '
            f'Map("code" -> e.code, "lineNumber" -> e.lineNumber.getOrElse(-1), '
            f'"filename" -> e.file.name.headOption.getOrElse(""))).l'
            f')).l.toJson'
        )
        return result if isinstance(result, list) else []

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """Find assignments/references to function as pointer."""
        result = self.query(
            f'cpg.identifier.name("{func_name}").inAssignment'
            f'.map(a => Map("code" -> a.code, '
            f'"filename" -> a.file.name.headOption.getOrElse(""), '
            f'"lineNumber" -> a.lineNumber.getOrElse(-1)))'
            f'.l.toJson'
        )
        return result if isinstance(result, list) else []
