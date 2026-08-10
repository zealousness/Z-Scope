from pathlib import Path

from zscope.orchestration.java_entry_discovery import JavaEntryDiscovery


class FakeJavaCodeIndex:
    language = "java"

    def __init__(self, methods):
        self.methods = methods
        self.list_calls = []
        self.impl_calls = []

    def list_functions(self, limit=10000, file_root=None):
        self.list_calls.append(file_root)
        names = []
        for name, value in self.methods.items():
            if file_root:
                file_path = Path(value.get("file", "src/main/java/demo/App.java"))
                try:
                    file_path.resolve().relative_to(Path(file_root).resolve())
                except ValueError:
                    continue
            names.append(name)
        return names[:limit]

    def get_function_impl(self, name, include_context=True, warn_missing=True):
        self.impl_calls.append((name, include_context))
        value = self.methods.get(name)
        if not value:
            return None
        return {
            "func_name": name,
            "qualified_name": value.get("qualified_name", name),
            "code": value["code"],
            "file": value.get("file", "src/main/java/demo/App.java"),
            "start_line": value.get("start_line", 10),
            "end_line": value.get("end_line", 14),
            "signature": value.get("signature", ""),
            "language": "java",
        }

    def get_file_snippet(self, file_path, start_line, end_line):
        for value in self.methods.values():
            if value.get("file", "src/main/java/demo/App.java") == file_path:
                return {
                    "file": file_path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "code": value.get("context", value["code"]),
                }
        return None


def test_spring_controller_mapping_is_discovered_as_java_web_entry() -> None:
    method = "com.example.UserController.createUser:void(com.example.UserRequest)"
    discovery = JavaEntryDiscovery(
        FakeJavaCodeIndex(
            {
                method: {
                    "context": """
@RestController
@RequestMapping("/users")
public class UserController {
    @PostMapping("/{id}")
    public void createUser(@RequestBody UserRequest request) {
        service.create(request);
    }
}
""",
                    "code": """
public void createUser(UserRequest request) {
    service.create(request);
}
""",
                }
            }
        )
    )

    result = discovery.discover()

    assert result.exposure_kind == "java_web_or_servlet"
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.function_name == method
    assert candidate.exposure == "java_web"
    assert "annotation:PostMapping" in candidate.reasons
    assert "route:/users /{id}" in candidate.reasons
    assert "request" in candidate.custom_prompt.lower()


def test_java_main_and_servlet_entries_are_discovered() -> None:
    main = "demo.App.main:void(java.lang.String[])"
    servlet = "demo.UserServlet.doPost:void(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)"
    discovery = JavaEntryDiscovery(
        FakeJavaCodeIndex(
            {
                main: {
                    "context": "public static void main(String[] args) { run(args); }",
                    "code": "public static void main(String[] args) { run(args); }",
                    "signature": "void(java.lang.String[])",
                },
                servlet: {
                    "context": """
protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    handle(request.getParameter("id"));
}
""",
                    "code": "protected void doPost(HttpServletRequest request, HttpServletResponse response) {}",
                    "signature": "void(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)",
                },
            }
        )
    )

    result = discovery.discover()

    by_exposure = {candidate.exposure: candidate for candidate in result.candidates}
    assert by_exposure["java_main"].function_name == main
    assert by_exposure["java_servlet"].function_name == servlet
    assert "public_static_main" in by_exposure["java_main"].reasons
    assert "servlet_method:doPost" in by_exposure["java_servlet"].reasons


def test_message_listener_and_scheduled_entries_are_discovered() -> None:
    listener = "demo.Worker.onMessage:void(java.lang.String)"
    scheduled = "demo.Worker.refresh:void()"
    discovery = JavaEntryDiscovery(
        FakeJavaCodeIndex(
            {
                listener: {
                    "file": "src/main/java/demo/Listener.java",
                    "context": """
@KafkaListener(topics = "orders")
public void onMessage(String payload) { service.consume(payload); }
""",
                    "code": "public void onMessage(String payload) { service.consume(payload); }",
                },
                scheduled: {
                    "file": "src/main/java/demo/ScheduledWorker.java",
                    "context": """
@Scheduled(fixedDelay = 1000)
public void refresh() { cache.reload(); }
""",
                    "code": "public void refresh() { cache.reload(); }",
                },
            }
        )
    )

    result = discovery.discover()

    by_exposure = {candidate.exposure: candidate for candidate in result.candidates}
    assert by_exposure["java_message_listener"].function_name == listener
    assert by_exposure["java_scheduled"].function_name == scheduled


def test_cli_command_and_library_public_api_entries_are_discovered() -> None:
    command = "demo.Cli.run:void()"
    library = "demo.LibraryApi.open:java.lang.String(java.lang.String)"
    discovery = JavaEntryDiscovery(
        FakeJavaCodeIndex(
            {
                command: {
                    "file": "src/main/java/demo/Cli.java",
                    "context": """
@Command(name = "scan")
public class Cli implements Runnable {
    public void run() { service.run(); }
}
""",
                    "code": "public void run() { service.run(); }",
                    "signature": "void()",
                },
                library: {
                    "file": "src/main/java/demo/LibraryApi.java",
                    "context": """
public class LibraryApi {
    public String open(String path) { return loader.open(path); }
}
""",
                    "code": "public String open(String path) { return loader.open(path); }",
                    "signature": "java.lang.String(java.lang.String)",
                },
            }
        )
    )

    result = discovery.discover()

    by_exposure = {candidate.exposure: candidate for candidate in result.candidates}
    assert by_exposure["java_cli_command"].function_name == command
    assert by_exposure["java_library_api"].function_name == library
    assert "public api" in by_exposure["java_library_api"].custom_prompt.lower()


def test_java_entry_discovery_filters_dto_accessors_and_builders() -> None:
    getter = "com.hmdp.dto.UserDTO.getId:java.lang.Long()"
    builder = "com.hmdp.dto.Result.build:com.hmdp.dto.Result()"
    service = "com.hmdp.service.ShopService.update:com.hmdp.dto.Result(com.hmdp.entity.Shop)"
    discovery = JavaEntryDiscovery(
        FakeJavaCodeIndex(
            {
                getter: {
                    "file": "src/main/java/com/hmdp/dto/UserDTO.java",
                    "context": "@Data public class UserDTO { public Long getId() { return id; } }",
                    "code": "public Long getId() { return id; }",
                    "signature": "java.lang.Long()",
                },
                builder: {
                    "file": "src/main/java/com/hmdp/dto/Result.java",
                    "context": "@Builder public class Result { public Result build() { return this; } }",
                    "code": "public Result build() { return this; }",
                    "signature": "com.hmdp.dto.Result()",
                },
                service: {
                    "file": "src/main/java/com/hmdp/service/ShopService.java",
                    "context": "public Result update(Shop shop) { return mapper.updateById(shop); }",
                    "code": "public Result update(Shop shop) { return mapper.updateById(shop); }",
                    "signature": "com.hmdp.dto.Result(com.hmdp.entity.Shop)",
                },
            }
        )
    )

    result = discovery.discover()

    names = [candidate.function_name for candidate in result.candidates]
    assert service in names
    assert getter not in names
    assert builder not in names


def test_java_entry_discovery_respects_search_root(tmp_path) -> None:
    allowed = tmp_path / "service" / "src/main/java/demo/Allowed.java"
    blocked = tmp_path / "other" / "src/main/java/demo/Blocked.java"
    allowed.parent.mkdir(parents=True)
    blocked.parent.mkdir(parents=True)
    allowed.write_text("", encoding="utf-8")
    blocked.write_text("", encoding="utf-8")
    discovery = JavaEntryDiscovery(
        FakeJavaCodeIndex(
            {
                "demo.Allowed.handle:void()": {
                    "file": str(allowed),
                    "context": '@GetMapping("/ok") public void handle() {}',
                    "code": "public void handle() {}",
                },
                "demo.Blocked.handle:void()": {
                    "file": str(blocked),
                    "context": '@GetMapping("/no") public void handle() {}',
                    "code": "public void handle() {}",
                },
            }
        ),
        search_root=tmp_path / "service",
    )

    result = discovery.discover()

    assert [candidate.function_name for candidate in result.candidates] == [
        "demo.Allowed.handle:void()"
    ]
