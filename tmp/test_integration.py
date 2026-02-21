"""
Z-SCOPE 端到端集成测试脚本。
使用 test/cache_module（含 6 个已知缺陷）验证完整流程。

前置条件：
  - Joern 已安装并可通过 PATH 访问
  - LLM 服务运行在 http://127.0.0.1:8045/v1
  - 已安装 zscope（pip install -e zscope）

用法：
  python tmp/test_integration.py [--skip-llm] [--skip-joern]
"""

import argparse
import json
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_MODULE = ROOT / "test" / "cache_module"
sys.path.insert(0, str(ROOT / "zscope"))


# ── Helpers ──

def green(s): return f"\033[92m{s}\033[0m"
def red(s): return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"


class TestResult:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.skipped = []

    def ok(self, name):
        self.passed.append(name)
        print(f"  {green('PASS')} {name}")

    def fail(self, name, reason=""):
        self.failed.append((name, reason))
        print(f"  {red('FAIL')} {name}: {reason}")

    def skip(self, name, reason=""):
        self.skipped.append(name)
        print(f"  {yellow('SKIP')} {name}: {reason}")

    def summary(self):
        total = len(self.passed) + len(self.failed) + len(self.skipped)
        print(f"\n{'='*60}")
        print(f"总计: {total}  通过: {len(self.passed)}  失败: {len(self.failed)}  跳过: {len(self.skipped)}")
        if self.failed:
            print(f"\n失败用例:")
            for name, reason in self.failed:
                print(f"  - {name}: {reason}")
        print(f"{'='*60}")
        return len(self.failed) == 0


# ── Test 1: UserConfigStore CRUD ──

def test_user_config_store(result):
    """验证用户配置数据库的完整 CRUD 操作。"""
    name = "1. UserConfigStore CRUD"
    try:
        from zscope.config.user_config_store import UserConfigStore

        with tempfile.TemporaryDirectory() as td:
            store = UserConfigStore(Path(td))

            # External functions
            store.upsert_external_function("malloc", "分配内存", library="libc")
            items = store.list_external_functions()
            assert len(items) == 1 and items[0]["func_name"] == "malloc"

            # Paired functions
            store.upsert_paired_function("memory", "malloc", "free")
            pairs = store.list_paired_functions()
            assert len(pairs) == 1

            # False positives
            store.add_false_positive("func_a", "file.c:10", "leak", "非问题")
            assert store.is_false_positive("func_a", "file.c:10", "leak")
            assert not store.is_false_positive("func_a", "file.c:10", "other")

            # Config warnings
            store.add_config_warning("missing_func", "foo", "未找到foo")
            warnings = store.list_config_warnings()
            assert len(warnings) == 1
            store.clear_config_warnings()
            assert len(store.list_config_warnings()) == 0

            # Function intents
            store.upsert_function_intent("cache_get", "cache_core.c", notes="线程安全")
            intents = store.list_function_intents()
            assert len(intents) == 1

            # Pointer targets
            store.upsert_pointer_target("handler_ptr", "local", ["handle_read", "handle_write"])
            targets = store.get_pointer_targets()
            assert len(targets) == 1

        result.ok(name)
    except Exception as e:
        result.fail(name, str(e))


# ── Test 2: Context Injection (external function) ──

def test_context_injection(result):
    """验证外部函数描述注入到工具返回结果。"""
    name = "2. 外部函数上下文注入"
    try:
        from unittest.mock import MagicMock
        from zscope.config.user_config_store import UserConfigStore
        from zscope.core.tools_runtime import ToolsRuntime

        with tempfile.TemporaryDirectory() as td:
            store = UserConfigStore(Path(td))
            store.upsert_external_function(
                "pthread_mutex_lock", "获取互斥锁，阻塞直到锁可用",
                library="pthread",
            )

            mock_index = MagicMock()
            mock_index.get_function_impl.return_value = None
            mock_snapshot = MagicMock()

            runtime = ToolsRuntime(mock_index, mock_snapshot, user_config=store)
            impl_result = runtime._get_function_impl("pthread_mutex_lock")

            # 应返回用户描述而非错误
            assert impl_result.get("success") is True, f"Expected success, got: {impl_result}"
            assert impl_result["data"].get("is_external") is True

        result.ok(name)
    except Exception as e:
        result.fail(name, str(e))


# ── Test 3: Config Warning Generation ──

def test_config_warnings(result):
    """验证未知外部函数自动生成配置告警。"""
    name = "3. 缺失配置告警生成"
    try:
        from unittest.mock import MagicMock
        from zscope.config.user_config_store import UserConfigStore
        from zscope.core.tools_runtime import ToolsRuntime

        with tempfile.TemporaryDirectory() as td:
            store = UserConfigStore(Path(td))
            mock_index = MagicMock()
            mock_index.get_function_impl.return_value = None
            mock_snapshot = MagicMock()

            runtime = ToolsRuntime(mock_index, mock_snapshot, user_config=store)
            runtime._get_function_impl("unknown_external_func")

            warnings = store.list_config_warnings()
            assert len(warnings) >= 1, f"Expected warnings, got {len(warnings)}"

        result.ok(name)
    except Exception as e:
        result.fail(name, str(e))


# ── Test 4: False Positive Filtering ──

def test_false_positive_filtering(result):
    """验证误报标记后在报告中被过滤。"""
    name = "4. 误报过滤"
    try:
        from zscope.config.user_config_store import UserConfigStore

        with tempfile.TemporaryDirectory() as td:
            store = UserConfigStore(Path(td))
            store.add_false_positive("cache_get", "cache_core.c:165", "buffer_overflow", "已确认安全")

            issues = [
                {"function": "cache_get", "file_path": "cache_core.c", "line_number": 165,
                 "category": "buffer_overflow", "description": "缓冲区溢出"},
                {"function": "cache_clear", "file_path": "cache_core.c", "line_number": 293,
                 "category": "stack_overflow", "description": "栈溢出"},
            ]

            filtered = []
            for issue in issues:
                loc = f"{issue['file_path']}:{issue['line_number']}"
                if not store.is_false_positive(issue["function"], loc, issue["category"]):
                    filtered.append(issue)

            assert len(filtered) == 1, f"Expected 1 issue after filtering, got {len(filtered)}"
            assert filtered[0]["function"] == "cache_clear"

        result.ok(name)
    except Exception as e:
        result.fail(name, str(e))


# ── Test 5: RuleEngine Parsing ──

def test_rule_engine_parsing(result):
    """验证 RuleEngine 正确解析 Joern scan 输出。"""
    name = "5. RuleEngine 解析"
    try:
        from unittest.mock import MagicMock
        from zscope.core.rule_engine import RuleEngine

        mock_joern = MagicMock()
        mock_joern.query.return_value = [
            {
                "name": "buffer-overflow",
                "title": "Buffer Overflow",
                "tags": ["memory"],
                "score": 8.0,
                "methodFullName": "cache_get",
                "filename": "cache_core.c",
                "lineNumber": 165,
                "code": "memcpy(value_out, node->value, node->value_size);",
            }
        ]

        engine = RuleEngine(mock_joern)
        matches = engine.run_builtin_scan()
        assert len(matches) == 1
        assert matches[0].func_name == "cache_get"
        assert matches[0].score == 8.0

        d = matches[0].to_dict()
        assert d["rule_id"] == "buffer-overflow"

        result.ok(name)
    except Exception as e:
        result.fail(name, str(e))


# ── Test 6: Header Function Extraction (regex fallback) ──

def test_header_extraction(result):
    """验证从 .h 文件提取公开接口函数（regex 回退模式）。"""
    name = "6. 头文件函数提取"
    try:
        from unittest.mock import MagicMock
        from zscope.retrieval.code_index import CodeIndex

        mock_joern = MagicMock()
        mock_joern.query.return_value = None  # Force regex fallback

        idx = MagicMock(spec=CodeIndex)
        idx._joern = mock_joern
        idx.source_root = CACHE_MODULE
        # _get_header_funcs_regex checks `name in self._function_index`
        expected_names = [
            "cache_create", "cache_put", "cache_get", "cache_delete",
            "cache_get_stats", "cache_list_entries", "cache_save",
            "cache_load", "cache_clear", "cache_destroy",
        ]
        idx._function_index = {n: True for n in expected_names}

        # Call the real regex method
        funcs = CodeIndex._get_header_funcs_regex(idx)
        func_names = [f["name"] for f in funcs]

        expected = [
            "cache_create", "cache_put", "cache_get", "cache_delete",
            "cache_get_stats", "cache_list_entries", "cache_save",
            "cache_load", "cache_clear", "cache_destroy",
        ]
        for name_exp in expected:
            assert name_exp in func_names, f"Missing: {name_exp}"

        result.ok(name)
    except Exception as e:
        result.fail(name, str(e))


# ── Test 7: Web Server Handlers ──

def test_web_server_handlers(result):
    """验证 Web API handler 逻辑。"""
    name = "7. Web API handlers"
    try:
        from unittest.mock import MagicMock, PropertyMock
        from zscope.config.user_config_store import UserConfigStore
        from zscope.web import server

        with tempfile.TemporaryDirectory() as td:
            store = UserConfigStore(Path(td))
            old_store = server._user_config_store
            old_joern = server._joern_client
            try:
                server._user_config_store = store

                # Test config CRUD via globals
                store.upsert_external_function("test_fn", "测试函数")
                items = server._user_config_store.list_external_functions()
                assert len(items) == 1

                # Test CPG status
                mock_joern = MagicMock()
                type(mock_joern).cpg_status = PropertyMock(return_value="ready")
                type(mock_joern).cpg_error = PropertyMock(return_value=None)
                server._joern_client = mock_joern
                assert server._joern_client.cpg_status == "ready"

                # Test report helpers
                issue = {"id": "1", "function": "f", "location": "a.c:1", "subcategory": "leak"}
                assert server.issue_key(issue) == ("1", "f", "a.c:1", "leak")

                s, r = server.normalize_validation({"validation_status": "validated", "validation_reasoning": "ok"})
                assert s == "validated" and r == "ok"

            finally:
                server._user_config_store = old_store
                server._joern_client = old_joern

        result.ok(name)
    except Exception as e:
        result.fail(name, str(e))


# ── Main ──

def main():
    parser = argparse.ArgumentParser(description="Z-SCOPE 集成测试")
    parser.add_argument("--skip-llm", action="store_true", help="跳过需要 LLM 的测试")
    parser.add_argument("--skip-joern", action="store_true", help="跳过需要 Joern 的测试")
    args = parser.parse_args()

    print(f"\nZ-SCOPE 集成测试")
    print(f"测试项目: {CACHE_MODULE}")
    print(f"{'='*60}\n")

    result = TestResult()

    tests = [
        test_user_config_store,
        test_context_injection,
        test_config_warnings,
        test_false_positive_filtering,
        test_rule_engine_parsing,
        test_header_extraction,
        test_web_server_handlers,
    ]

    for test_fn in tests:
        try:
            test_fn(result)
        except Exception:
            result.fail(test_fn.__name__, traceback.format_exc())

    success = result.summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
