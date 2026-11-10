"""Acceptance workload executed by the bundle Python in an isolated container.

There is no fake backend and no LLM call. This is a distribution smoke test,
separate from the protected formal accuracy benchmark.
"""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(os.environ["Z_SCOPE_BUNDLE_ROOT"])
WORK = Path.cwd()
CHECKS = {}
LOGS = {}


class PageAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "script" and attributes.get("src"):
            self.urls.append(attributes["src"])
        elif tag == "link" and attributes.get("rel") == "stylesheet":
            self.urls.append(attributes["href"])


def reports():
    from zscope.reporting.report import FinalReport, ReportGenerator
    from zscope.reporting.sarif_exporter import save_sarif_report

    report = FinalReport(entry_function="portable-smoke", overall_verdict="no_issue_found")
    generator = ReportGenerator(WORK)
    result = generator.save_json_report(report)
    assert json.loads(result.read_text())["entry_function"] == "portable-smoke"
    assert "portable-smoke" in generator.save_markdown_report(report).read_text()
    sarif = save_sarif_report(result, WORK / "report.sarif", source_root=WORK)
    assert json.loads(sarif.read_text())["version"] == "2.1.0"
    CHECKS["reports"] = True


def command(name, *args, timeout=300, input=None):
    result = subprocess.run(
        [str(ROOT / "bin" / name), *map(str, args)],
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input,
    )
    LOGS[name] = {
        "returncode": result.returncode,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-12000:],
    }
    if result.returncode:
        raise RuntimeError(f"{name} failed ({result.returncode}): {result.stderr[-3000:]}")
    return result.stdout


def common():
    assert os.getuid() != 0
    CHECKS["ordinary-user"] = True
    assert not os.access(ROOT, os.W_OK)
    CHECKS["readonly"] = True
    assert " " in str(ROOT) and " " in str(WORK)
    link = WORK / "linked-zscope"
    link.symlink_to(ROOT / "bin/zscope")
    subprocess.run([str(link), "--help"], check=True, capture_output=True)
    assert command("python", "-c", "import os; print(os.getcwd())").strip() == str(WORK)
    CHECKS["relocation"] = True
    command("zscope", "--help")
    CHECKS["cli"] = True
    command("python", "-c", "import openai, requests, cpgqls_client, yaml, click, zscope.cli.cli, zscope.mcp.server, zscope.web.server")
    CHECKS["runtime-imports"] = True
    context = ssl.create_default_context()
    assert context.get_ca_certs()
    with sqlite3.connect(":memory:") as db:
        db.execute("create table sample (value text)")
        db.execute("insert into sample values (?)", ("portable",))
        assert db.execute("select value from sample").fetchone() == ("portable",)
    CHECKS["ssl-sqlite"] = True


def cpp():
    assert "22.1.7" in command("clangd", "--version")
    assert "18.1.0" in command("clang", "--version")
    source = WORK / "main.cpp"
    source.write_text(
        "#include <vector>\n#include <cstdio>\nint twice(int x) { return x * 2; }\nint main() { std::vector<int> v{21}; return twice(v[0]) == 42 ? 0 : 1; }\n"
    )
    command("g++", "-std=c++17", source, "-o", WORK / "gcc-example")
    subprocess.run([str(WORK / "gcc-example")], check=True)
    command("clang++", "-std=c++17", source, "-o", WORK / "clang-example")
    subprocess.run([str(WORK / "clang-example")], check=True)
    CHECKS["compile"] = True
    build_project = WORK.parent / "cmake-project"
    build_project.mkdir()
    (build_project / "main.cpp").write_text(source.read_text())
    (build_project / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\nproject(portable LANGUAGES CXX)\nadd_executable(portable main.cpp)\ntarget_compile_features(portable PRIVATE cxx_std_17)\n"
    )
    for generator, folder in (("Ninja", "ninja-build"), ("Unix Makefiles", "make-build")):
        command(
            "cmake", "-S", build_project, "-B", WORK.parent / folder, "-G", generator, timeout=600
        )
        command("cmake", "--build", WORK.parent / folder, "--parallel", "2", timeout=600)
        subprocess.run([str(WORK.parent / folder / "portable")], check=True)
    assert command("pkg-config", "--version").strip()
    CHECKS["build-tools"] = True
    c_source = WORK / "sample.c"
    c_source.write_text(
        "#include <stdlib.h>\nint main(void) { int *p = malloc(sizeof(int)); if (!p) return 1; *p = 42; free(p); return 0; }\n"
    )
    os.environ["LLVM_CC_NAME"] = "/unexpected-host-clang22"
    os.environ["LLVM_COMPILER_PATH"] = "/unexpected-host-llvm22"
    command("gclang", "-g", "-O0", c_source, "-o", WORK / "sample")
    command("get-bc", WORK / "sample")
    assert (WORK / "sample.bc").stat().st_size > 0
    command("llvm-link", WORK / "sample.bc", "-o", WORK / "linked.bc")
    assert "main" in command("llvm-nm", WORK / "linked.bc")
    CHECKS["bitcode"] = True
    CHECKS["llvm18-isolation"] = True
    from zscope.retrieval.svf_runner import SvfRunner

    runner = SvfRunner(timeout=600)
    ander = runner.run_ander(WORK / "linked.bc", WORK / "ander")
    LOGS["wpa"] = {"success": ander.success, "stderr": ander.stderr[-12000:]}
    assert ander.success and ander.output_file and ander.output_file.is_file()
    CHECKS["wpa"] = True
    saber = runner.run_saber(WORK / "linked.bc", WORK / "saber")
    LOGS["saber"] = {"success": saber.success, "stderr": saber.stderr[-12000:]}
    assert saber.success
    CHECKS["saber"] = True
    # Compilation database includes the same sysroot that compiled the TU. An
    # experiment may supply another toolchain through its own compile database.
    manifest = json.loads((ROOT / "bundle.json").read_text())
    triple = manifest["target_triple"]
    arguments = [
        str(ROOT / "bin/clang++"),
        "-std=c++17",
        f"--sysroot={ROOT / 'tools/gcc/sysroot'}",
        f"--gcc-toolchain={ROOT / 'tools/gcc'}",
        "-c",
        str(source),
    ]
    (WORK / "compile_commands.json").write_text(
        json.dumps([{"directory": str(WORK), "file": str(source), "arguments": arguments}])
    )
    output = subprocess.run(
        [str(ROOT / "bin/clangd"), f"--check={source}", f"--compile-commands-dir={WORK}"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    LOGS["clangd-check"] = {
        "stdout": output.stdout,
        "stderr": output.stderr,
        "returncode": output.returncode,
    }
    assert output.returncode == 0 and "0 errors" in output.stderr
    CHECKS["clangd-headers"] = True
    from zscope.retrieval.clang_extractor import ClangExtractor

    extractor = ClangExtractor(WORK, str(ROOT / "bin/clangd"), WORK, max_threads=2)
    try:
        assert extractor.start() and extractor.open_document(source)
        document = {"uri": source.as_uri()}
        position = {"line": 2, "character": 5}
        assert extractor.send_request("textDocument/ast", {"textDocument": document})
        CHECKS["clangd-ast"] = True
        assert extractor.get_document_symbols(source)
        symbols = extractor.send_request(
            "textDocument/symbolInfo", {"textDocument": document, "position": position}
        )
        assert symbols and symbols[0].get("usr")
        CHECKS["clangd-usr"] = True
        assert extractor.send_request(
            "textDocument/references",
            {"textDocument": document, "position": position, "context": {"includeDeclaration": True}},
        )
        CHECKS["clangd-references"] = True
        items = extractor.prepare_call_hierarchy(source, 3, 5)
        assert items and extractor.get_outgoing_calls(items[0])
        CHECKS["clangd-calls"] = True
        changed = source.read_text() + "int incremental_symbol() { return twice(7); }\n"
        source.write_text(changed)
        extractor.send_notification(
            "textDocument/didChange",
            {
                "textDocument": {"uri": source.as_uri(), "version": 2},
                "contentChanges": [{"text": changed}],
            },
        )
        symbols = extractor.get_document_symbols(source)
        assert symbols and any(item.get("name") == "incremental_symbol" for item in symbols)
        CHECKS["clangd-incremental"] = True
        # Finish the fixture's background index before starting the separate
        # MCP test. Killing it early leaves missing .idx files whose later
        # creation legitimately changes the batch include-directory snapshot.
        assert extractor.wait_for_indexing(timeout=120, idle_threshold=5.0)
    finally:
        extractor.stop()


    from zscope.retrieval.clang_backend import ClangBackend
    backend = ClangBackend(max_threads=2)
    try:
        assert backend.initialize(str(WORK), compile_commands_path=str(WORK / "compile_commands.json"))
        assert backend.get_method("twice")
        CHECKS["clang-index"] = True
    finally:
        backend.close()
    cached = ClangBackend(max_threads=2)
    try:
        assert cached.initialize(str(WORK), compile_commands_path=str(WORK / "compile_commands.json"))
        assert cached.get_method("twice") and cached._extractor is None
        CHECKS["clang-cache"] = True
    finally:
        cached.close()


def interfaces(profile):
    # Exercise actual public servers against the already indexed sample. Their
    # initialization uses the selected backend and must not require an LLM.
    project = WORK
    config = project / "zscope.yaml"
    data = {
        "llms": {
            "default": {
                "base_urls": ["http://127.0.0.1:9/v1"],
                "models": ["not-used-by-smoke"],
                "api_key": "not-used",
            }
        },
        "project": {
            "root": str(project),
            "source_root": str(project),
            "entry_function": "main",
        },
        "indexing": {"backend": "clang", "max_clangd_threads": 2},
    }
    if profile == "cpp":
        data["project"]["compile_commands_path"] = str(WORK / "compile_commands.json")
    data["concurrency"] = {
        key: 1
        for key in (
            "entry_workers",
            "validator_workers",
            "investigator_workers",
            "evidence_completion_workers",
            "index_workers",
            "llm_max_inflight",
        )
    }
    if profile == "cpp":
        data["concurrency"]["svf_workers"] = 1
    config.write_text(json.dumps(data))
    web_log = WORK / "webui.log"
    web_output = web_log.open("w")
    web = subprocess.Popen(
        [str(ROOT / "bin/zscope"), "--config", str(config), "--dashboard"],
        stdout=web_output,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if web.poll() is not None:
                raise RuntimeError("WebUI terminated: " + web_log.read_text()[-4000:])
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/", timeout=5) as response:
                    page = response.read().decode()
                    assert response.status == 200 and "<html" in page.lower()
                assets = PageAssets()
                assets.feed(page)
                assert assets.urls and "@import" not in page
                for relative in [*assets.urls, "offline_template.html"]:
                    assert not urlsplit(relative).scheme and not urlsplit(relative).netloc
                    with urllib.request.urlopen(
                        urljoin("http://127.0.0.1:8000/", relative), timeout=5
                    ) as resource:
                        assert resource.status == 200 and len(resource.read()) > 100
                CHECKS["webui-offline-assets"] = True
                CHECKS["webui"] = True
                break
            except OSError:
                time.sleep(1)
        assert CHECKS.get("webui"), "WebUI readiness timeout: " + web_log.read_text()[-4000:]
    finally:
        web.terminate()
        try:
            web.wait(timeout=20)
        except subprocess.TimeoutExpired:
            web.kill()
            web.wait()
        web_output.close()
        LOGS["webui"] = {"output": web_log.read_text()[-12000:]}
    request = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "portable-smoke", "version": "1"},
                },
            }
        )
        + "\n"
    )
    request += json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
    request += (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": {"uri": "zscope://knowledge/functions"},
            }
        )
        + "\n"
    )
    output = command("zscope", "--config", config, "--mcp-stdio", timeout=1200, input=request)
    responses = {}
    for header in re.finditer(r"Content-Length: \d+\n\n", output):
        value, _ = json.JSONDecoder().raw_decode(output[header.end() :])
        assert "error" not in value
        responses[value["id"]] = value["result"]
    assert responses[1]["protocolVersion"] and responses[2]["tools"]
    functions = json.loads(responses[3]["contents"][0]["text"])["functions"]
    assert functions and "twice" in json.dumps(functions)
    CHECKS["mcp-index"] = True
    CHECKS["mcp"] = True


def main():
    profile = json.loads((ROOT / "bundle.json").read_text())["profile"]
    result = {
        "glibc": os.confstr("CS_GNU_LIBC_VERSION").split()[-1],
        "uid": os.getuid(),
        "arch": platform.machine(),
        "network": "none",
        "bundle_mount": "ro",
        "passed": False,
        "checks": CHECKS,
        "logs": LOGS,
    }
    try:
        common()
        assert profile == "cpp", "v1.2 delivery supports the C/C++ profile"
        cpp()
        interfaces(profile)
        reports()
        result["passed"] = True
    except Exception as exc:
        result["failure_reason"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        (WORK.parent / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
