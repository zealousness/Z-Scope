import json

from zscope.config.config import ConfigLoader
from zscope.orchestration.entry_discovery import EntryDiscovery
from zscope.retrieval.code_index import CodeIndex


class FakeCodeIndex:
    def __init__(self, functions):
        self.functions = functions
        self.list_calls = []
        self.impl_calls = []

    def get_header_declared_functions(self, header_files=None):
        return []

    def list_functions(self, limit=10000, file_root=None):
        self.list_calls.append(file_root)
        return list(self.functions)[:limit]

    def get_function_impl(self, name, include_context=True, warn_missing=True):
        self.impl_calls.append(
            {
                "name": name,
                "include_context": include_context,
                "warn_missing": warn_missing,
            }
        )
        value = self.functions.get(name)
        if value is None:
            return None
        if isinstance(value, dict):
            code = value["code"]
            file_path = value.get("file", "src/demo.c")
            start_line = value.get("start_line", 1)
        else:
            code = value
            file_path = "src/demo.c"
            start_line = 1
        return {
            "code": code,
            "file": file_path,
            "start_line": start_line,
        }


def test_communication_prompt_guides_caller_side_validation_for_wrappers():
    discovery = EntryDiscovery(
        FakeCodeIndex(
            {
                "MsgRecv": """
ssize_t MsgRecv(int fd, char *buf, size_t len) {
    return recv(fd, buf, len, 0);
}
""",
            }
        )
    )

    result = discovery.discover()

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.function_name == "MsgRecv"
    assert candidate.exposure == "communication"
    assert "get_callers" in candidate.custom_prompt
    assert "caller-side parsing and validation" in candidate.custom_prompt


def test_tls_receive_is_discovered_as_communication_input():
    discovery = EntryDiscovery(
        FakeCodeIndex(
            {
                "TlsRecv": """
int TlsRecv(SSL *ssl, unsigned char *buf, size_t len) {
    return SSL_read(ssl, buf, len);
}
""",
            }
        )
    )

    result = discovery.discover()

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.function_name == "TlsRecv"
    assert candidate.exposure == "communication"
    assert "calls:SSL_read" in candidate.reasons


def test_user_input_prompt_guides_caller_side_validation_for_file_wrappers():
    discovery = EntryDiscovery(
        FakeCodeIndex(
            {
                "ReadConfigLine": """
char *ReadConfigLine(FILE *fp, char *buf, size_t len) {
    return fgets(buf, len, fp);
}
""",
            }
        )
    )

    result = discovery.discover()

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.function_name == "ReadConfigLine"
    assert candidate.exposure == "other_user_input"
    assert "get_callers" in candidate.custom_prompt
    assert "caller-side validation and sinks" in candidate.custom_prompt


def test_symbol_inputs_are_discovered_without_call_syntax():
    discovery = EntryDiscovery(
        FakeCodeIndex(
            {
                "Main": """
int Main(int argc, char **argv) {
    if (argc > 1) {
        return dispatch(argv[1]);
    }
    return 0;
}
""",
            }
        )
    )

    result = discovery.discover()

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.function_name == "Main"
    assert candidate.exposure == "other_user_input"
    assert "input:argv" in candidate.reasons


def test_pthread_create_discovers_thread_entry_not_creator():
    discovery = EntryDiscovery(
        FakeCodeIndex(
            {
                "StartWorkers": """
int StartWorkers(void) {
    pthread_t tid;
    return pthread_create(&tid, NULL, WorkerMain, NULL);
}
""",
                "WorkerMain": """
static void* WorkerMain(void* arg) {
    return arg;
}
""",
            }
        )
    )

    result = discovery.discover()

    assert [candidate.function_name for candidate in result.candidates] == ["WorkerMain"]
    candidate = result.candidates[0]
    assert candidate.exposure == "thread"
    assert "thread_entry:pthread_create" in candidate.reasons


def test_search_root_limits_discovered_entries_to_that_directory(tmp_path):
    project_root = tmp_path
    source_root = project_root
    search_root = project_root / "src" / "net"
    search_root.mkdir(parents=True)
    (project_root / "src" / "cli").mkdir(parents=True)

    discovery = EntryDiscovery(
        FakeCodeIndex(
            {
                "NetRecv": {
                    "code": "int NetRecv(int fd, char *buf, size_t len) { return recv(fd, buf, len, 0); }",
                    "file": "src/net/net.c",
                },
                "CliMain": {
                    "code": "int CliMain(int argc, char **argv) { return argc > 1 ? dispatch(argv[1]) : 0; }",
                    "file": "src/cli/main.c",
                },
            }
        ),
        project_root=project_root,
        source_root=source_root,
        search_root=search_root,
    )

    result = discovery.discover()

    assert [candidate.function_name for candidate in result.candidates] == ["NetRecv"]


def test_search_root_is_pushed_into_function_listing(tmp_path):
    project_root = tmp_path
    search_root = project_root / "src" / "net"
    search_root.mkdir(parents=True)
    fake_index = FakeCodeIndex(
        {
            "NetRecv": {
                "code": "int NetRecv(int fd, char *buf, size_t len) { return recv(fd, buf, len, 0); }",
                "file": "src/net/net.c",
            },
        }
    )

    discovery = EntryDiscovery(
        fake_index,
        project_root=project_root,
        source_root=project_root,
        search_root=search_root,
    )

    discovery.discover()

    assert fake_index.list_calls == [search_root.resolve()]


def test_code_index_lists_only_functions_under_file_root(tmp_path):
    net_dir = tmp_path / "src" / "net"
    cli_dir = tmp_path / "src" / "cli"
    net_dir.mkdir(parents=True)
    cli_dir.mkdir(parents=True)
    (net_dir / "net.c").write_text(
        "int NetRecv(int fd, char *buf, unsigned long len) { return recv(fd, buf, len, 0); }\n",
        encoding="utf-8",
    )
    (cli_dir / "main.c").write_text(
        "int CliMain(int argc, char **argv) { return argc; }\n",
        encoding="utf-8",
    )
    code_index = CodeIndex(tmp_path, source_root=tmp_path)

    try:
        assert code_index.list_functions(limit=20, file_root=net_dir) == ["NetRecv"]
    finally:
        code_index.close()


def test_code_index_file_root_filter_uses_source_root_relative_paths(tmp_path):
    project_root = tmp_path / "project"
    source_root = project_root / "src"
    net_dir = source_root / "net"
    cli_dir = source_root / "cli"
    net_dir.mkdir(parents=True)
    cli_dir.mkdir(parents=True)
    (net_dir / "net.c").write_text(
        "int NetRecv(int fd, char *buf, unsigned long len) { return recv(fd, buf, len, 0); }\n",
        encoding="utf-8",
    )
    (cli_dir / "main.c").write_text(
        "int CliMain(int argc, char **argv) { return argc; }\n",
        encoding="utf-8",
    )
    code_index = CodeIndex(project_root, source_root=source_root)

    try:
        assert code_index.list_functions(limit=20, file_root="net") == ["NetRecv"]
    finally:
        code_index.close()


def test_discovery_result_can_be_written_as_entry_functions_list_payload():
    discovery = EntryDiscovery(
        FakeCodeIndex(
            {
                "MsgRecv": """
ssize_t MsgRecv(int fd, char *buf, size_t len) {
    return recv(fd, buf, len, 0);
}
""",
            }
        )
    )

    payload = discovery.discover().to_entry_functions_payload()

    assert payload["functions"][0]["function_name"] == "MsgRecv"
    assert payload["functions"][0]["custom_prompt"]
    assert payload["functions"][0]["exposure"] == "communication"


def test_public_api_prompt_requires_callee_sink_audit():
    class HeaderCodeIndex(FakeCodeIndex):
        def get_header_declared_functions(self, header_files=None):
            return [{"name": "PublicFacade", "filename": "include/api.h", "lineNumber": 1}]

    discovery = EntryDiscovery(
        HeaderCodeIndex(
            {
                "PublicFacade": "int PublicFacade(const char *msg) { return InternalSink(msg); }",
            }
        )
    )

    payload = discovery.discover().to_entry_functions_payload()

    prompt = payload["functions"][0]["custom_prompt"]
    assert "follow its callees" in prompt
    assert "concrete vulnerable callee location" in prompt


def test_search_root_skips_header_declarations_before_impl_lookup(tmp_path):
    project_root = tmp_path
    source_root = project_root
    search_root = project_root / "src" / "api"
    search_root.mkdir(parents=True)
    (project_root / "vendor" / "boring").mkdir(parents=True)

    class HeaderCodeIndex(FakeCodeIndex):
        def get_header_declared_functions(self, header_files=None):
            return [
                {
                    "name": "_goboringcrypto_OPENSSL_malloc",
                    "filename": "vendor/boring/crypto.h",
                    "lineNumber": 10,
                },
                {
                    "name": "PublicFacade",
                    "filename": "src/api/public.h",
                    "lineNumber": 20,
                },
            ]

    fake_index = HeaderCodeIndex(
        {
            "PublicFacade": {
                "code": "int PublicFacade(int fd, char *buf, size_t len) { return recv(fd, buf, len, 0); }",
                "file": "src/api/public.c",
            },
        }
    )

    discovery = EntryDiscovery(
        fake_index,
        project_root=project_root,
        source_root=source_root,
        search_root=search_root,
    )

    result = discovery.discover()

    assert [candidate.function_name for candidate in result.candidates] == ["PublicFacade"]
    assert [call["name"] for call in fake_index.impl_calls] == ["PublicFacade", "PublicFacade"]
    assert all(call["warn_missing"] is True for call in fake_index.impl_calls)


def test_config_loader_accepts_absolute_entry_discovery_search_root(tmp_path):
    project_root = tmp_path
    search_root = project_root / "src"
    search_root.mkdir()
    config_path = project_root / "zscope.json"
    config_path.write_text(
        json.dumps(
            {
                "llms": {"default": {"model": "dummy"}},
                "project": {
                    "root": str(project_root),
                    "source_root": str(project_root),
                    "entry_discovery": {
                        "enabled": True,
                        "search_root": str(search_root),
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    config = ConfigLoader.load(config_path)

    assert config.project.entry_discovery.search_root == search_root.resolve()
