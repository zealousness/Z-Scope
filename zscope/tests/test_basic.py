import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from zscope.utils import compute_code_hash, compute_semantic_fingerprint, extract_function_calls
from zscope.config import ProjectConfig

def test_utils_hash():
    code = "int main() { return 0; }"
    assert compute_code_hash(code) == compute_code_hash(code)
    assert compute_code_hash(code) != compute_code_hash("void foo(){}")

def test_utils_semantic_fingerprint():
    code1 = """
    int add(int a, int b) {
        // This calculates sum
        return a + b;
    }
    """
    code2 = """
    int add(int a, int b) {
        /* Different comment */
        return a + b; 
    }
    """
    # Should be identical despite comment changes and whitespace
    assert compute_semantic_fingerprint(code1) == compute_semantic_fingerprint(code2)

    code3 = "int add(int a, int b) { return a - b; }"
    assert compute_semantic_fingerprint(code1) != compute_semantic_fingerprint(code3)

def test_extract_function_calls():
    code = """
    void foo() {
        bar(1);
        if (x) {
            baz();
        }
        return;
    }
    """
    calls = extract_function_calls(code)
    assert "bar" in calls
    assert "baz" in calls
    assert "if" not in calls
    assert "return" not in calls

def test_project_config():
    with TemporaryDirectory() as tmp:
        path = Path(tmp)
        config = ProjectConfig(
            project_root=path,
            entry_function="main",
            task_description="test"
        )
        assert config.project_root == path.resolve()
