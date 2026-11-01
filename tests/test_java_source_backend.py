import json
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.config.config import ConfigLoader
from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.evidence import backend_profile_for_code_index
from zscope.core.candidates.backend_signals import java_provider_signal_to_candidate
from zscope.core.candidates.java_evidence import normalize_java_candidate
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.java_models import JavaCallEdge, JavaFlowSignal
from zscope.retrieval.java_signal_providers import ExternalJavaSignalProvider
from zscope.retrieval.java_models import normalize_java_evidence_precision
from zscope.retrieval.java_source_backend import JavaSourceBackend
from zscope.retrieval.java_unified_backend import JavaUnifiedBackend


def _fake_sidecar_script(tmp_path: Path, *, frontend: str, exit_code: int = 0) -> Path:
    script = tmp_path / f"{frontend}_sidecar.py"
    if exit_code:
        script.write_text(
            "import sys\n"
            f"sys.stderr.write('{frontend} failed')\n"
            f"raise SystemExit({exit_code})\n",
            encoding="utf-8",
        )
        return script
    precision = "source_level_exact" if frontend == "spoon" else "source_level_approx"
    payload = {
        "frontend": frontend,
        "classes": [
            {
                "name": "App",
                "full_name": "com.example.App",
                "fullName": "com.example.App",
                "package": "com.example",
                "file": "src/main/java/com/example/App.java",
                "start_line": 1,
                "end_line": 3,
                "kind": "class",
                "annotations": [],
                "fields": {},
                "methods": [
                    {
                        "name": "run",
                        "qualified_name": "com.example.App.run:void()",
                        "fullName": "com.example.App.run:void()",
                        "class_name": "App",
                        "class_full_name": "com.example.App",
                        "package": "com.example",
                        "file": "src/main/java/com/example/App.java",
                        "start_line": 2,
                        "end_line": 2,
                        "signature": "void()",
                        "return_type": "void",
                        "parameters": [],
                        "annotations": [],
                        "calls": [],
                        "is_public": True,
                        "frontend": frontend,
                        "precision": precision,
                    }
                ],
            }
        ],
    }
    script.write_text(
        "import json\n" f"print(json.dumps({payload!r}))\n",
        encoding="utf-8",
    )
    return script


def _simple_java_project(tmp_path: Path, *, with_pom: bool = True) -> None:
    if with_pom:
        (tmp_path / "pom.xml").write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion></project>\n',
            encoding="utf-8",
        )
    source = tmp_path / "src/main/java/com/example/App.java"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "package com.example;\n"
        "public class App { public void run() { helper(); } public void helper() {} }\n",
        encoding="utf-8",
    )


def test_java_source_backend_indexes_framework_metadata(tmp_path: Path) -> None:
    source = tmp_path / "src/main/java/com/example/UserController.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n"
        "\n"
        "@RestController\n"
        '@RequestMapping("/users")\n'
        "public class UserController {\n"
        '    @PostMapping("/{id}")\n'
        "    public String create(@RequestBody String body) {\n"
        "        return service.save(body);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    db_path = tmp_path / ".zscope_knowledge/java_structure.db"
    backend = JavaSourceBackend(frontend="builtin", structure_db_path=str(db_path))
    assert backend.initialize(str(tmp_path), project_root=tmp_path)

    index = backend.build_function_index()
    key = "com.example.UserController.create:String(String)"
    assert key in index
    method = index[key]
    assert method["language"] == "java"
    assert method["class_annotations"][0]["name"] == "RestController"
    assert method["annotations"][0]["name"] == "PostMapping"
    assert method["framework_semantics"]["entry"]["is_entry"] is True
    assert method["framework_semantics"]["sources"][0]["kind"] == "http_request_body"
    assert method["structure_precision"] == "regex_or_builtin_fallback"
    assert backend.structure_db is not None
    assert backend.structure_db.method_count() == 1
    assert backend.structure_db.class_count() == 1


def test_java_structure_frontend_cli_mvp_contract(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>demo</groupId><artifactId>app</artifactId><version>1.0</version>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.springframework.boot</groupId>\n"
        "      <artifactId>spring-boot-starter-web</artifactId>\n"
        "      <version>3.3.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )
    controller = tmp_path / "src/main/java/com/example/UserController.java"
    service = tmp_path / "src/main/java/com/example/UserService.java"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        "package com.example;\n"
        "@RestController\n"
        '@RequestMapping("/users")\n'
        "public class UserController {\n"
        "    private UserService service;\n"
        "    @PostMapping\n"
        "    public String create(@RequestBody String body) {\n"
        "        return service.save(body);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    service.write_text(
        "package com.example;\n"
        "public class UserService {\n"
        "    public String save(String body) { return body.trim(); }\n"
        "}\n",
        encoding="utf-8",
    )
    script = Path(__file__).resolve().parents[1] / "tools" / "java_structure_frontend.py"

    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--frontend",
            "javaparser",
            "--project-root",
            str(tmp_path),
            str(tmp_path),
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["frontend"] == "javaparser"
    assert (
        "maven:org.springframework.boot:spring-boot-starter-web:3.3.0"
        in payload["build"]["classpath_entries"]
    )
    assert {row["full_name"] for row in payload["classes"]} == {
        "com.example.UserController",
        "com.example.UserService",
    }

    db_path = tmp_path / ".zscope_knowledge/java_structure.db"
    backend = JavaSourceBackend(
        frontend="javaparser",
        extractor_command=[
            sys.executable,
            str(script),
            "--frontend",
            "javaparser",
            "--project-root",
            str(tmp_path),
            "{source_root}",
        ],
        structure_db_path=str(db_path),
    )
    assert backend.initialize(str(tmp_path), project_root=tmp_path)

    index = backend.build_function_index()
    method = index["com.example.UserController.create:String(String)"]
    assert method["structure_frontend"] == "javaparser"
    assert method["structure_precision"] == "source_level_approx"
    assert method["framework_semantics"]["entry"]["is_entry"] is True
    assert method["framework_semantics"]["sources"][0]["kind"] == "http_request_body"
    assert backend.get_callees("com.example.UserController.create:String(String)")[0][
        "fullName"
    ] == ("com.example.UserService.save:String(String)")
    assert backend.structure_db is not None
    assert backend.structure_db.class_count() == 2
    assert backend.structure_db.method_count() == 2


def test_java_structure_auto_uses_spoon_first(monkeypatch, tmp_path: Path) -> None:
    _simple_java_project(tmp_path)
    spoon_script = _fake_sidecar_script(tmp_path, frontend="spoon")

    def fake_command(self, frontend, source_root, project_root):
        if frontend == "spoon":
            return [sys.executable, str(spoon_script), "{source_root}"], ""
        return [], "unexpected frontend"

    monkeypatch.setattr(JavaSourceBackend, "_command_for_frontend", fake_command)
    backend = JavaSourceBackend(frontend="auto")

    assert backend.initialize(str(tmp_path), project_root=tmp_path)
    method = backend.build_function_index()["com.example.App.run:void()"]

    assert backend.frontend == "spoon"
    assert method["structure_frontend_actual"] == "spoon"
    assert method["structure_precision"] == "source_level_exact"
    assert method["structure_frontend_attempts"][0]["status"] == "success"


def test_java_structure_auto_falls_back_from_spoon_to_javaparser(
    monkeypatch, tmp_path: Path
) -> None:
    _simple_java_project(tmp_path)
    spoon_script = _fake_sidecar_script(tmp_path, frontend="spoon", exit_code=7)
    javaparser_script = _fake_sidecar_script(tmp_path, frontend="javaparser")

    def fake_command(self, frontend, source_root, project_root):
        if frontend == "spoon":
            return [sys.executable, str(spoon_script), "{source_root}"], ""
        if frontend == "javaparser":
            return [sys.executable, str(javaparser_script), "{source_root}"], ""
        return [], "unexpected frontend"

    monkeypatch.setattr(JavaSourceBackend, "_command_for_frontend", fake_command)
    backend = JavaSourceBackend(frontend="auto")

    assert backend.initialize(str(tmp_path), project_root=tmp_path)
    method = backend.build_function_index()["com.example.App.run:void()"]

    assert backend.frontend == "javaparser"
    assert method["structure_frontend_actual"] == "javaparser"
    assert method["structure_precision"] == "source_level_approx"
    assert [item["status"] for item in method["structure_frontend_attempts"]] == [
        "failed",
        "success",
    ]
    assert "spoon failed" in method["structure_frontend_fallback_reason"]


def test_java_structure_auto_falls_back_to_builtin(monkeypatch, tmp_path: Path) -> None:
    _simple_java_project(tmp_path, with_pom=False)
    spoon_script = _fake_sidecar_script(tmp_path, frontend="spoon", exit_code=7)
    javaparser_script = _fake_sidecar_script(tmp_path, frontend="javaparser", exit_code=8)

    def fake_command(self, frontend, source_root, project_root):
        if frontend == "spoon":
            return [sys.executable, str(spoon_script), "{source_root}"], ""
        if frontend == "javaparser":
            return [sys.executable, str(javaparser_script), "{source_root}"], ""
        return [], "unexpected frontend"

    monkeypatch.setattr(JavaSourceBackend, "_command_for_frontend", fake_command)
    backend = JavaSourceBackend(frontend="auto")

    assert backend.initialize(str(tmp_path), project_root=tmp_path)
    method = backend.build_function_index()["com.example.App.run:void()"]

    assert backend.frontend == "builtin"
    assert method["structure_frontend_actual"] == "builtin"
    assert method["structure_precision"] == "regex_or_builtin_fallback"
    assert [item["status"] for item in method["structure_frontend_attempts"]] == [
        "failed",
        "failed",
        "success",
    ]
    assert "javaparser failed" in method["structure_frontend_fallback_reason"]


def test_java_structure_spoon_attempt_requires_pom_even_with_custom_command(tmp_path: Path) -> None:
    _simple_java_project(tmp_path, with_pom=False)
    backend = JavaSourceBackend(
        frontend="auto", extractor_command=["java", "-jar", "custom-spoon.jar"]
    )

    command, reason = backend._command_for_frontend("spoon", tmp_path, tmp_path)

    assert command == []
    assert "pom.xml" in reason


def test_java_structure_default_spoon_command_is_offline_safe(monkeypatch, tmp_path: Path) -> None:
    _simple_java_project(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/mvn")
    monkeypatch.setattr(
        JavaSourceBackend,
        "_ensure_default_spoon_jar",
        classmethod(lambda _cls, _source, _project: ("/opt/zscope/spoon.jar", "")),
    )

    command, reason = JavaSourceBackend(frontend="auto")._command_for_frontend(
        "spoon", tmp_path, tmp_path
    )

    assert reason == ""
    assert command[:3] == ["java", "-jar", "/opt/zscope/spoon.jar"]
    assert "--force-refresh" not in command
    assert command[-1] == "{source_root}"


def test_spoon_structure_frontend_maven_project_is_wired() -> None:
    root = Path(__file__).resolve().parents[1]
    pom = root / "tools" / "java-structure-spoon" / "pom.xml"
    exporter = (
        root
        / "tools"
        / "java-structure-spoon"
        / "src"
        / "main"
        / "java"
        / "com"
        / "zscope"
        / "tools"
        / "SpoonStructureExporter.java"
    )

    pom_text = pom.read_text(encoding="utf-8")
    exporter_text = exporter.read_text(encoding="utf-8")

    assert "<artifactId>spoon-core</artifactId>" in pom_text
    assert "<spoon.version>11.4.0</spoon.version>" in pom_text
    assert "<artifactId>lombok</artifactId>" in pom_text
    assert "<lombok.version>1.18.46</lombok.version>" in pom_text
    assert "<mainClass>com.zscope.tools.SpoonStructureExporter</mainClass>" in pom_text
    assert "new MavenLauncher(" in exporter_text
    assert 'Files.deleteIfExists(args.projectRoot.resolve("spoon.classpath.tmp"))' in exporter_text
    assert "--lombok-processor" in exporter_text
    assert "lombok.launch.AnnotationProcessorHider$AnnotationProcessor" in exporter_text
    assert "lombok_ecj_agent_incompatible" in exporter_text
    assert "source_level_exact" in exporter_text
    assert '"classes"' in exporter_text
    assert normalize_java_evidence_precision("source_level_exact") == "source_level_exact"


@pytest.mark.skipif(
    shutil.which("mvn") is None or shutil.which("java") is None,
    reason="real Java sidecar contract requires Maven and Java",
)
def test_spoon_structure_frontend_lombok_processor_real_cli_contract(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    pom = root / "tools" / "java-structure-spoon" / "pom.xml"
    jar = (
        root / "tools" / "java-structure-spoon" / "target" / "zscope-java-structure-spoon-0.1.0.jar"
    )
    subprocess.run(
        ["mvn", "-q", "-f", str(pom), "-DskipTests", "package"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
    )
    (tmp_path / "pom.xml").write_text(
        """
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>lombok-spoon-fixture</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <lombok.version>1.18.46</lombok.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.projectlombok</groupId>
      <artifactId>lombok</artifactId>
      <version>${lombok.version}</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.13</version>
    </dependency>
  </dependencies>
</project>
""".lstrip(),
        encoding="utf-8",
    )
    source = tmp_path / "src/main/java/com/example/LombokController.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n"
        "import lombok.extern.slf4j.Slf4j;\n"
        "@Slf4j\n"
        "public class LombokController {\n"
        '  public void run(String value) { log.info("{}", value); }\n'
        "}\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            "java",
            "-jar",
            str(jar),
            "--project-root",
            str(tmp_path),
            "--lombok-processor",
            "on",
            str(tmp_path),
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    classes = {row["fullName"]: row for row in payload["classes"]}
    assert payload["frontend"] == "spoon"
    assert payload["build"]["annotation_processing"]["enabled"] is True
    assert payload["build"]["annotation_processing"]["detected_lombok"] is True
    assert (
        "lombok_ecj_agent_incompatible"
        in payload["build"]["annotation_processing"]["fallback_reason"]
    )
    assert "com.example.LombokController" in classes
    assert classes["com.example.LombokController"]["fields"]["log"] == "org.slf4j.Logger"
    method = next(
        item for item in classes["com.example.LombokController"]["methods"] if item["name"] == "run"
    )
    assert method["structure_precision"] == "source_level_exact"
    assert any(call["name"] == "info" for call in method["calls"])

    off_proc = subprocess.run(
        [
            "java",
            "-jar",
            str(jar),
            "--project-root",
            str(tmp_path),
            "--lombok-processor",
            "off",
            str(tmp_path),
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if off_proc.returncode == 0:
        off_payload = json.loads(off_proc.stdout)
        assert off_payload["build"]["annotation_processing"]["enabled"] is False
    else:
        assert (
            "log cannot be resolved" in off_proc.stderr
            or "Spoon structure export failed" in off_proc.stderr
        )


def test_javaparser_structure_frontend_maven_project_is_wired() -> None:
    root = Path(__file__).resolve().parents[1]
    pom = root / "tools" / "java-structure-javaparser" / "pom.xml"
    exporter = (
        root
        / "tools"
        / "java-structure-javaparser"
        / "src"
        / "main"
        / "java"
        / "com"
        / "zscope"
        / "tools"
        / "JavaParserStructureExporter.java"
    )

    pom_text = pom.read_text(encoding="utf-8")
    exporter_text = exporter.read_text(encoding="utf-8")

    assert "<artifactId>javaparser-core</artifactId>" in pom_text
    assert "<mainClass>com.zscope.tools.JavaParserStructureExporter</mainClass>" in pom_text
    assert "StaticJavaParser.parse" in exporter_text
    assert "source_level_approx" in exporter_text
    assert '"classes"' in exporter_text


@pytest.mark.skipif(
    shutil.which("mvn") is None or shutil.which("java") is None,
    reason="real Java sidecar contract requires Maven and Java",
)
def test_javaparser_structure_frontend_real_cli_contract(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    pom = root / "tools" / "java-structure-javaparser" / "pom.xml"
    jar = (
        root
        / "tools"
        / "java-structure-javaparser"
        / "target"
        / "zscope-java-structure-javaparser-0.1.0.jar"
    )
    subprocess.run(
        ["mvn", "-q", "-f", str(pom), "-DskipTests", "package"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
    )
    _simple_java_project(tmp_path)
    controller = tmp_path / "src/main/java/com/example/UserController.java"
    controller.write_text(
        "package com.example;\n"
        "@RestController\n"
        "public class UserController {\n"
        "  @PostMapping\n"
        "  public String create(String body) { return body.trim(); }\n"
        "}\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        ["java", "-jar", str(jar), "--project-root", str(tmp_path), str(tmp_path)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    classes = {row["fullName"]: row for row in payload["classes"]}
    method = classes["com.example.UserController"]["methods"][0]
    assert payload["frontend"] == "javaparser"
    assert method["frontend"] == "javaparser"
    assert method["structure_precision"] == "source_level_approx"
    assert method["annotations"][0]["name"] == "PostMapping"
    assert method["calls"][0]["name"] == "trim"


def test_code_index_uses_java_source_backend(tmp_path: Path) -> None:
    source = tmp_path / "src/main/java/com/example/App.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n"
        "public class App {\n"
        "    public void main(String arg) { helper(arg); }\n"
        "    public void helper(String arg) { System.out.println(arg); }\n"
        "}\n",
        encoding="utf-8",
    )
    backend = JavaSourceBackend(frontend="builtin")
    code_index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    result = code_index.get_function_impl("com.example.App.main:void(String)", warn_missing=False)

    assert result is not None
    assert result["language"] == "java"
    assert result["qualified_name"] == "com.example.App.main:void(String)"
    assert result["callees"] == ["helper"]
    assert "com.example.App.helper:void(arg)" not in code_index.list_functions(limit=20)
    assert backend_profile_for_code_index(code_index) == "java_source"


def test_java_unified_backend_exposes_structure_profile(tmp_path: Path) -> None:
    source = tmp_path / "src/main/java/com/example/App.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n" "public class App { public void run() {} }\n",
        encoding="utf-8",
    )
    backend = JavaUnifiedBackend(structure_frontend="builtin", signal_backends=[])
    code_index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    assert code_index.get_function_impl("run", warn_missing=False) is not None
    assert backend_profile_for_code_index(code_index) == "java_unified"
    assert backend.java_signal_capabilities() == []
    assert backend.java_signal_status() == []


def test_config_loader_parses_java_structure_and_signal_options(tmp_path: Path) -> None:
    config = tmp_path / "zscope.yaml"
    config.write_text(
        f"""
config_version: 2
project:
  language: java
  entry_function: demo.App.run:void()
llms:
  default:
    api_key: test
    base_urls: [http://localhost/v1]
    models: [test-model]
scan:
  task: audit
indexing:
  backend: java_unified
  java:
    structure_frontend: spoon
    extractor_command:
      - java
      - -jar
      - tools/java-structure-spoon/target/zscope-java-structure-spoon-0.1.0.jar
      - --project-root
      - "{{source_root}}"
      - "{{source_root}}"
    signals: [sootup, codeql, joern]
    provider_commands:
      codeql: [python, run_codeql.py, "{{source_root}}"]
concurrency:
  entry_workers: 2
  validator_workers: 2
  investigator_workers: 1
  evidence_completion_workers: 2
  index_workers: 2
  llm_max_inflight: 2
""",
        encoding="utf-8",
    )

    cfg = ConfigLoader.load(config)

    assert cfg.indexing.backend == "java_unified"
    assert cfg.indexing.java_structure_frontend == "spoon"
    assert cfg.indexing.java_structure_extractor_command == [
        "java",
        "-jar",
        "tools/java-structure-spoon/target/zscope-java-structure-spoon-0.1.0.jar",
        "--project-root",
        "{source_root}",
        "{source_root}",
    ]
    assert cfg.indexing.java_signal_backends == ["sootup", "codeql", "joern"]
    assert cfg.indexing.java_signal_provider_commands["codeql"] == [
        "python",
        "run_codeql.py",
        "{source_root}",
    ]


def test_config_loader_rejects_removed_scan_after_discovery(tmp_path: Path) -> None:
    config = tmp_path / "zscope.yaml"
    config.write_text(
        f"""
config_version: 2
project:
  language: java
  entry_function: demo.App.run:void()
  entry_discovery:
    enabled: true
    scan_after_discovery: false
llms:
  default:
    api_key: test
    base_urls: [http://localhost/v1]
    models: [test-model]
indexing:
  backend: java_source
concurrency:
  entry_workers: 2
  validator_workers: 2
  investigator_workers: 1
  evidence_completion_workers: 2
  index_workers: 2
  llm_max_inflight: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="scan_after_discovery"):
        ConfigLoader.load(config)


def test_config_loader_defaults_java_structure_to_auto(tmp_path: Path) -> None:
    config = tmp_path / "zscope.yaml"
    config.write_text(
        f"""
config_version: 2
project:
  language: java
  entry_function: demo.App.run:void()
llms:
  default:
    api_key: test
    base_urls: [http://localhost/v1]
    models: [test-model]
scan:
  task: audit
indexing:
  backend: java_source
concurrency:
  entry_workers: 2
  validator_workers: 2
  investigator_workers: 1
  evidence_completion_workers: 2
  index_workers: 2
  llm_max_inflight: 2
""",
        encoding="utf-8",
    )

    cfg = ConfigLoader.load(config)

    assert cfg.indexing.java_structure_frontend == "auto"


def test_java_provider_signal_converts_to_evidence_only_candidate() -> None:
    signal = JavaFlowSignal(
        rule_id="codeql_path_injection",
        category="sql_injection",
        provider="codeql",
        precision="exact_flow",
        source={
            "expression": "request parameter q",
            "kind": "java_http_request",
            "file": "src/App.java",
            "line": 10,
        },
        sink={
            "operation": "Statement.execute(q)",
            "kind": "java_sql_execution",
            "file": "src/App.java",
            "line": 20,
            "function": "demo.App.search:void(String)",
        },
        path=[{"method": "demo.App.search:void(String)", "line": 20}],
        score=8.5,
    )

    candidate = normalize_java_candidate(
        java_provider_signal_to_candidate(
            signal.to_dict(), entry_func="demo.App.search:void(String)"
        )
    )

    assert candidate["candidate_source"] == "java_codeql_signal"
    assert candidate["candidate_role"] == "evidence_only"
    assert candidate["evidence_pack"]["candidate_is_conclusion"] is False
    assert candidate["evidence_pack"]["validation_required"] is True
    assert candidate["evidence_pack"]["precision"] == "exact_flow"
    assert candidate["evidence_pack"]["confidence_tier"] == "exact"


def test_external_java_signal_provider_accepts_object_schema_and_caches_per_entry(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider.py"
    script.write_text(
        "import json, sys\n"
        "entry = sys.argv[-1]\n"
        "print(json.dumps({\n"
        "  'provider': 'sootup',\n"
        "  'call_edges': [{'caller': entry, 'callee': entry + '.sink', 'call_name': 'sink', 'file': 'src/App.java', 'line': 7}],\n"
        "  'signals': [{'provider': 'sootup', 'rule_id': 'r_' + entry, 'category': 'ssrf', 'source': {'file': 'src/App.java', 'line': 3}, 'sink': {'file': 'src/App.java', 'line': 7}, 'path': [{'method': entry}], 'score': 7.0}]\n"
        "}))\n",
        encoding="utf-8",
    )
    provider = ExternalJavaSignalProvider(
        "sootup", command=[sys.executable, str(script), "{entry}"]
    )
    assert provider.initialize(tmp_path, tmp_path, None)

    first = provider.collect_flow_signals("A")
    second = provider.collect_flow_signals("B")
    first_edges = provider.collect_call_edges("A")
    second_edges = provider.collect_call_edges("B")

    assert first[0].rule_id == "r_A"
    assert second[0].rule_id == "r_B"
    assert first_edges[0].caller == "A"
    assert second_edges[0].caller == "B"


def test_java_unified_backend_merges_provider_call_edges(tmp_path: Path) -> None:
    source = tmp_path / "src/main/java/com/example/App.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n" "public class App { public void run() {} }\n",
        encoding="utf-8",
    )

    class FakeProvider:
        name = "sootup"

        def collect_call_edges(self, entry_func: str = ""):
            return [
                JavaCallEdge(
                    caller="com.example.App.run:void()",
                    callee="com.example.App.helper:void()",
                    call_name="helper",
                    file="src/main/java/com/example/App.java",
                    line=2,
                    call_type="sootup_call_graph",
                    precision="typed_callgraph_flow",
                )
            ]

        def collect_rule_matches(self, entry_func: str = ""):
            return []

        def collect_flow_signals(self, entry_func: str = ""):
            return []

        def collect_taint_signals(self, entry_func: str = ""):
            return []

        def capabilities(self):
            return SimpleNamespace(to_dict=lambda: {"provider": "sootup"})

        def status(self):
            return SimpleNamespace(to_dict=lambda: {"provider": "sootup", "available": True})

        def close(self):
            return None

    backend = JavaUnifiedBackend(structure_frontend="builtin", signal_backends=[])
    code_index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)
    backend._providers = [FakeProvider()]

    callees = backend.get_callees("com.example.App.run:void()")
    callers = backend.get_callers("com.example.App.helper:void()")

    assert any(item.get("callee") == "com.example.App.helper:void()" for item in callees)
    assert any(item.get("caller") == "com.example.App.run:void()" for item in callers)
    assert code_index.get_function_impl("run", warn_missing=False) is not None


def test_analyzer_converts_java_provider_dict_signal_to_candidate() -> None:
    class FakeBackend:
        def collect_java_signal_matches(self, entry_func: str = ""):
            return [
                {
                    "provider": "sootup",
                    "rule_id": "sootup_sql_path",
                    "category": "sql_injection",
                    "precision": "typed_callgraph_flow",
                    "source": {"file": "src/main/java/App.java", "line": 3, "function": entry_func},
                    "sink": {
                        "file": "src/main/java/App.java",
                        "line": 7,
                        "function": "demo.App.sink:void(String)",
                        "operation": "Statement.execute",
                    },
                    "path": [{"method": entry_func}, {"method": "demo.App.sink:void(String)"}],
                }
            ]

    analyzer = Analyzer.__new__(Analyzer)
    analyzer.code_index = SimpleNamespace(backend=lambda: FakeBackend())
    analyzer._candidate_backend_profile = lambda: "java_unified"
    analyzer._reachable_function_names_from_entry = lambda *args, **kwargs: {
        "demo.App.run:void()",
        "demo.App.sink:void(String)",
    }

    candidates = analyzer._detect_joern_cpg_candidates(
        {"entry_func": "demo.App.run:void()"},
    )

    assert len(candidates) == 1
    assert candidates[0]["candidate_source"] == "java_sootup_signal"
    assert candidates[0]["candidate_role"] == "evidence_only"
    assert candidates[0]["evidence_pack"]["validation_notes"]


def test_codeql_sarif_parser_emits_exact_flow_signal(tmp_path: Path) -> None:
    module_path = Path(__file__).resolve().parents[1] / "tools" / "run_codeql_java.py"
    spec = importlib.util.spec_from_file_location("run_codeql_java", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "java/sql-injection",
                                "properties": {"tags": ["security", "sql"]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "java/sql-injection",
                        "level": "warning",
                        "message": {"text": "SQL injection path"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/main/java/App.java"},
                                    "region": {"startLine": 20},
                                },
                                "message": {"text": "sink"},
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": "src/main/java/App.java"
                                                        },
                                                        "region": {"startLine": 10},
                                                    },
                                                    "message": {"text": "source"},
                                                }
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": "src/main/java/App.java"
                                                        },
                                                        "region": {"startLine": 20},
                                                    },
                                                    "message": {"text": "sink"},
                                                }
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    }

    payload = module.sarif_to_payload(sarif, tmp_path, tmp_path, "demo.App.search:void(String)")

    assert payload["provider"] == "codeql"
    signal = payload["signals"][0]
    assert signal["provider"] == "codeql"
    assert signal["category"] == "sql_injection"
    assert signal["precision"] == "exact_flow"
    assert signal["source"]["line"] == 10
    assert signal["sink"]["line"] == 20


@pytest.mark.skipif(sys.platform == "win32", reason="CodeQL CLI is supported through Linux/WSL")
def test_codeql_wrapper_degrades_when_query_suite_is_missing(tmp_path: Path) -> None:
    module_path = Path(__file__).resolve().parents[1] / "tools" / "run_codeql_java.py"
    spec = importlib.util.spec_from_file_location("run_codeql_java", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fake_codeql = tmp_path / "codeql"
    fake_codeql.write_text(
        "#!/usr/bin/env sh\n" "echo 'query pack missing' >&2\n" "exit 2\n",
        encoding="utf-8",
    )
    fake_codeql.chmod(0o755)

    suite, reason = module.resolve_query_suite(str(fake_codeql), "")
    payload = module.degraded_payload(reason)

    assert suite == ""
    assert payload["provider"] == "codeql"
    assert payload["signals"] == []
    assert "query pack missing" in payload["metadata"]["degraded_reason"]
    assert "Install/configure CodeQL Java queries" in payload["metadata"]["degraded_reason"]
