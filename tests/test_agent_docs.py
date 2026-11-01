from pathlib import Path
from typing import Any, Dict

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE_DOC_NAMES = (
    "execution-orchestration.md",
    "analysis-pipeline.md",
    "retrieval-backends.md",
    "agent-runtime.md",
    "configuration-state.md",
    "review-memory.md",
    "wiki.md",
    "interfaces-reporting.md",
    "benchmarking.md",
)
MODULE_DIR = ROOT / "docs" / "modules"
MODULE_DOCS = tuple(MODULE_DIR / name for name in MODULE_DOC_NAMES)
HANDOFF_DOCS = (
    ROOT / "AGENTS.md",
    MODULE_DIR / "README.md",
    *MODULE_DOCS,
    ROOT / "docs" / "range-benchmark.md",
)
MOJIBAKE_MARKERS = (
    "锛",
    "銆",
    "鐨勮",
    "浣跨敤",
    "缁撴灉",
    "鏂囨。",
)


def _read_utf8(path: Path) -> str:
    data = path.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM is not allowed: {path}"
    assert b"\r" not in data, f"Only LF line endings are allowed: {path}"
    text = data.decode("utf-8", errors="strict")
    assert text.endswith("\n"), f"Final newline is required: {path}"
    return text


def _read_contract(path: Path) -> Dict[str, Any]:
    text = _read_utf8(path)
    assert text.startswith("---\n"), f"Missing YAML frontmatter: {path}"
    parts = text.split("---\n", 2)
    assert len(parts) == 3, f"Unterminated YAML frontmatter: {path}"
    metadata = yaml.safe_load(parts[1])
    assert isinstance(metadata, dict), f"Invalid YAML frontmatter: {path}"
    assert metadata.get("doc_contract") == "zscope-module-v1"
    for field in ("covers", "sources", "tests"):
        values = metadata.get(field)
        assert isinstance(values, list) and values, f"Missing {field}: {path}"
        assert all(isinstance(value, str) and value for value in values)
        assert len(values) == len(set(values)), f"Duplicate {field} entries: {path}"
    return metadata


def test_handoff_docs_are_strict_utf8_lf_without_mojibake() -> None:
    for path in HANDOFF_DOCS:
        assert path.is_file(), f"Missing handoff document: {path}"
        text = _read_utf8(path)
        for marker in MOJIBAKE_MARKERS:
            assert marker not in text, f"Possible mojibake marker {marker!r} in {path}"


def test_module_contract_covers_every_top_level_package_once() -> None:
    covered = []
    for path in MODULE_DOCS:
        metadata = _read_contract(path)
        for relative in metadata["covers"]:
            module_path = ROOT / relative
            assert module_path.is_dir(), f"Covered module does not exist: {relative}"
            assert (
                module_path.parent == ROOT / "zscope"
            ), f"covers must name a direct zscope child: {relative}"
            covered.append(relative)

        for field in ("sources", "tests"):
            for relative in metadata[field]:
                assert (ROOT / relative).exists(), f"Missing {field} path: {relative}"

    assert len(covered) == len(set(covered)), "A top-level package is covered more than once"
    actual = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "zscope").iterdir()
        if path.is_dir() and path.name != "__pycache__"
    }
    assert set(covered) == actual


def test_root_and_index_link_every_module_document() -> None:
    root_text = _read_utf8(ROOT / "AGENTS.md")
    index_text = _read_utf8(MODULE_DIR / "README.md")

    for name in MODULE_DOC_NAMES:
        assert f"docs/modules/{name}" in root_text
        assert f"]({name})" in index_text

    for route in ("使用者路线", "开发者路线", "Range Benchmark 路线"):
        assert route in root_text


def test_root_config_and_runtime_agent_boundaries_are_explicit() -> None:
    text = _read_utf8(ROOT / "AGENTS.md")
    assert "-c/--config" in text
    assert "`./zscope.yaml`" in text
    assert "不是其他目标项目的全局配置入口" in text
    assert "YAML 所在目录为唯一工程根" in text
    assert "不再接受公共 `project.root` 或 `source_root` 字段" in text
    assert "`zscope/agents/*/AGENT.md`" in text
    assert "产品运行时" in text
    assert not (ROOT / "AGENT.md").exists(), "Use the standard root name AGENTS.md only"


def test_range_plan_distinguishes_linux_wsl_and_windows() -> None:
    text = _read_utf8(ROOT / "docs" / "range-benchmark.md")
    for phrase in (
        "Linux",
        "Windows",
        "WSL",
        "Windows",
        "benchmark/ground_truth.json",
    ):
        assert phrase in text
    assert "health/index/scan 环境不含 truth 路径" in text


def test_repository_markdown_encoding_configuration() -> None:
    editorconfig = (ROOT / ".editorconfig").read_text(encoding="utf-8")
    assert "[*.md]" in editorconfig
    assert "charset = utf-8" in editorconfig
    assert "end_of_line = lf" in editorconfig
    assert "insert_final_newline = true" in editorconfig

    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "*.md text eol=lf" in attributes.splitlines()
