from pathlib import Path

from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.java_joern_backend import JavaJoernBackend


class FakeJoern:
    def __init__(self, result):
        self.result = result
        self.queries = []

    def query(self, cpgql: str):
        self.queries.append(cpgql)
        return self.result

    def start_server(self):
        return True

    def stop_server(self):
        pass


def test_java_joern_backend_indexes_methods_by_full_name() -> None:
    backend = JavaJoernBackend(
        joern_client=FakeJoern(
            [
                {
                    "name": "createUser",
                    "fullName": "com.example.UserController.createUser:com.example.User(java.lang.String)",
                    "filename": "src/main/java/com/example/UserController.java",
                    "lineNumber": 12,
                    "lineNumberEnd": 24,
                    "signature": "com.example.User(java.lang.String)",
                    "code": "public User createUser(String name)",
                    "annotations": [
                        {
                            "name": "PostMapping",
                            "fullName": "org.springframework.web.bind.annotation.PostMapping",
                            "code": '@PostMapping("/users")',
                            "lineNumber": 11,
                        }
                    ],
                    "parameterAnnotations": [],
                    "classAnnotations": [
                        {
                            "name": "RestController",
                            "fullName": "org.springframework.web.bind.annotation.RestController",
                            "code": "@RestController",
                            "lineNumber": 8,
                        }
                    ],
                }
            ]
        )
    )

    index = backend.build_function_index()

    key = "com.example.UserController.createUser:com.example.User(java.lang.String)"
    assert key in index
    assert index[key]["language"] == "java"
    assert index[key]["class_name"] == "UserController"
    assert index[key]["package"] == "com.example"
    assert "createUser" in index[key]["aliases"]
    assert index[key]["declaration_code"] == "public User createUser(String name)"
    assert index[key]["annotations"][0]["name"] == "PostMapping"
    assert index[key]["class_annotations"][0]["name"] == "RestController"
    assert index[key]["framework_semantics"]["entry"]["is_entry"] is True
    assert index[key]["framework_semantics"]["entry"]["http_methods"] == ["POST"]
    assert '"annotations" -> m.annotation' in backend.joern_client.queries[0]


class JavaBackendStub:
    def __init__(self, source_file: Path) -> None:
        self.source_file = source_file
        self.callee_queries = []
        self.closed = False

    def build_function_index(self):
        full_name = "com.example.UserController.createUser:void(java.lang.String)"
        return {
            full_name: {
                "name": "createUser",
                "qualified_name": full_name,
                "method_full_name": full_name,
                "file": str(self.source_file),
                "start_line": 5,
                "end_line": 7,
                "signature": "void(java.lang.String)",
                "language": "java",
                "class_name": "UserController",
                "package": "com.example",
                "aliases": ["createUser", "com.example.UserController.createUser"],
            }
        }

    def get_method(self, name: str):
        return None

    def get_method_callees(self, name: str, limit: int = 30):
        self.callee_queries.append(name)
        return [{"name": "save", "fullName": "com.example.UserService.save:void()"}]

    def close(self):
        self.closed = True


def test_code_index_returns_java_method_metadata_and_alias_lookup(tmp_path) -> None:
    source = tmp_path / "src/main/java/com/example/UserController.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n"
        "\n"
        "public class UserController {\n"
        "    // creates a user\n"
        "    public void createUser(String name) {\n"
        "        service.save(name);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    backend = JavaBackendStub(source)

    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)
    result = index.get_function_impl("createUser", warn_missing=False)

    assert result is not None
    assert result["language"] == "java"
    assert result["class_name"] == "UserController"
    assert result["package"] == "com.example"
    assert (
        result["qualified_name"] == "com.example.UserController.createUser:void(java.lang.String)"
    )
    assert result["callees"] == ["save"]
    assert backend.callee_queries == [
        "com.example.UserController.createUser:void(java.lang.String)"
    ]


class JavaDeclarationBackendStub:
    def __init__(self, source_file: Path) -> None:
        self.source_file = source_file

    def build_function_index(self):
        full_name = "com.example.UserMapper.findBySort:java.lang.Object(java.lang.String)"
        return {
            full_name: {
                "name": "findBySort",
                "qualified_name": full_name,
                "method_full_name": full_name,
                "file": str(self.source_file),
                "start_line": 4,
                "end_line": 5,
                "signature": "java.lang.Object(java.lang.String)",
                "language": "java",
                "class_name": "UserMapper",
                "package": "com.example",
                "declaration_code": "abstract Object findBySort(String sort)",
                "annotations": [
                    {
                        "name": "Select",
                        "fullName": "org.apache.ibatis.annotations.Select",
                        "code": '@Select("select * from users order by ${sort}")',
                        "lineNumber": 4,
                    }
                ],
                "parameter_annotations": [],
                "class_annotations": [],
                "framework_semantics": {
                    "frameworks": ["mybatis"],
                    "sql_templates": [
                        {
                            "framework": "mybatis",
                            "annotation": "Select",
                            "uses_text_substitution": True,
                            "text_substitution_variables": ["sort"],
                        }
                    ],
                },
                "aliases": ["findBySort", "com.example.UserMapper.findBySort"],
            }
        }

    def get_method(self, name: str):
        return None

    def get_method_callees(self, name: str, limit: int = 30):
        return []

    def close(self):
        pass


def test_code_index_returns_java_declaration_snapshot_with_annotations(tmp_path) -> None:
    source = tmp_path / "src/main/java/com/example/UserMapper.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n"
        "\n"
        "public interface UserMapper {\n"
        '    @Select("select * from users order by ${sort}")\n'
        "    Object findBySort(String sort);\n"
        "}\n",
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=JavaDeclarationBackendStub(source),
    )

    result = index.get_function_impl("findBySort", warn_missing=False)

    assert result is not None
    assert result["declaration_only"] is True
    assert result["language"] == "java"
    assert result["annotations"][0]["name"] == "Select"
    assert result["framework_semantics"]["frameworks"] == ["mybatis"]
    assert "${sort}" in result["code"]
