import json
import subprocess
import hashlib
from collections import Counter
from pathlib import Path

from zscope.retrieval.build_llvm import BitcodeBuilder


def _write_compile_commands(tmp_path: Path) -> tuple[Path, Path]:
    source_root = tmp_path / "project"
    source_root.mkdir()
    (source_root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text(
        json.dumps([
            {
                "directory": str(source_root),
                "command": "cc -c main.c",
                "file": "main.c",
            }
        ]),
        encoding="utf-8",
    )
    return source_root, compile_commands


def _write_multi_compile_commands(tmp_path: Path, count: int) -> tuple[Path, Path]:
    source_root = tmp_path / "project"
    source_root.mkdir()
    commands = []
    for idx in range(count):
        source = source_root / f"file_{idx}.c"
        source.write_text(f"int f_{idx}(void) {{ return {idx}; }}\n", encoding="utf-8")
        commands.append(
            {
                "directory": str(source_root),
                "command": f"cc -c {source.name}",
                "file": source.name,
            }
        )
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text(json.dumps(commands), encoding="utf-8")
    return source_root, compile_commands


def _fake_bitcode_tools(monkeypatch, calls: list[str]) -> None:
    def fake_run(cmd, *args, **kwargs):
        calls.append(Path(cmd[0]).name)
        if Path(cmd[0]).name == "gclang":
            out_path = Path(cmd[cmd.index("-o") + 1])
            cwd = Path(kwargs.get("cwd") or ".")
            source_text = ""
            for arg in cmd:
                candidate = Path(str(arg))
                if candidate.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                    continue
                candidate_path = candidate if candidate.is_absolute() else cwd / candidate
                if candidate_path.exists():
                    source_text = candidate_path.read_text(encoding="utf-8")
                    break
            digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
            out_path.write_text(f"object {digest}\n", encoding="utf-8")
        elif Path(cmd[0]).name == "get-bc":
            object_text = Path(cmd[1]).read_text(encoding="utf-8")
            Path(str(cmd[1]) + ".bc").write_text(f"bitcode {object_text}", encoding="utf-8")
        elif Path(cmd[0]).name == "llvm-link":
            out_path = Path(cmd[cmd.index("-o") + 1])
            out_path.write_text("merged\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)


def _build_once(source_root: Path, compile_commands: Path, output_dir: Path, timeout: int = 1800):
    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=output_dir,
        gclang_path="gclang",
        get_bc_path="get-bc",
        llvm_link_path="llvm-link",
        timeout=timeout,
    )
    return builder.build()


def test_sanitize_rewrites_make_filename_define_from_shell_command() -> None:
    command = (
        r"""cc -D__FILENAME__='\"$notdir \$(patsubst \"%\",%,<SOURCE>))\"' """
        r"""-DKEEP=1 -c src/main.c"""
    )

    args = BitcodeBuilder._split_command(command)
    cleaned = BitcodeBuilder._sanitize_args(args, "main.c")

    assert "-DKEEP=1" in cleaned
    assert '-D__FILENAME__="main.c"' in cleaned
    assert not any("patsubst" in arg for arg in cleaned)


def test_bitcode_build_reuses_unchanged_tu_and_merged_bitcode(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    first = _build_once(source_root, compile_commands, output_dir)
    assert first["default"].exists()
    assert calls == ["gclang", "get-bc", "llvm-link"]

    calls.clear()
    second = _build_once(source_root, compile_commands, output_dir)

    assert second == first
    assert calls == []


def test_bitcode_build_reuses_outputs_when_only_timeout_changes(tmp_path: Path, monkeypatch) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    _build_once(source_root, compile_commands, output_dir, timeout=7)
    calls.clear()
    _build_once(source_root, compile_commands, output_dir, timeout=99)

    assert calls == []


def test_bitcode_build_rebuilds_when_source_changes(tmp_path: Path, monkeypatch) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    _build_once(source_root, compile_commands, output_dir)
    calls.clear()
    (source_root / "main.c").write_text("int main(void) { return 1; }\n", encoding="utf-8")
    _build_once(source_root, compile_commands, output_dir)

    assert calls == ["gclang", "get-bc", "llvm-link"]


def test_link_reuses_existing_merged_bitcode_from_previous_scope_plan(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    output_dir = tmp_path / ".zscope_bc"
    output_dir.mkdir()
    bc_path = output_dir / "tu_0_main.o.bc"
    merged_path = output_dir / "merged_default.bc"
    bc_path.write_text("bitcode\n", encoding="utf-8")
    merged_path.write_text("merged\n", encoding="utf-8")
    calls: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=output_dir,
        gclang_path="gclang",
        get_bc_path="get-bc",
        llvm_link_path="llvm-link",
    )

    result = builder._link_all(
        [bc_path],
        "default",
        previous_selected_bcs={str(bc_path.resolve())},
    )

    assert result == merged_path
    assert calls == []
    assert builder.reused_linked_groups == {"default"}


def test_bitcode_build_compiles_multiple_tus_before_single_link(tmp_path: Path, monkeypatch) -> None:
    source_root, compile_commands = _write_multi_compile_commands(tmp_path, 6)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    result = _build_once(source_root, compile_commands, output_dir)

    assert result["default"].exists()
    assert Counter(calls) == Counter({"gclang": 6, "get-bc": 6, "llvm-link": 1})
    assert BitcodeBuilder._build_worker_count(100) <= 8


def test_sanitize_rewrites_filename_define_fragments_from_whitespace_split() -> None:
    args = [
        "cc",
        r"""-D__FILENAME__='\"$notdir""",
        r"""\$(patsubst""",
        r"""\"%\",%,main.c))\"'""",
        "-DKEEP=1",
        "-c",
        "src/main.c",
    ]

    cleaned = BitcodeBuilder._sanitize_args(args, "main.c")

    assert cleaned == ["cc", '-D__FILENAME__="main.c"', "-DKEEP=1", "-c", "src/main.c"]


def test_sanitize_rewrites_split_d_filename_define_pair() -> None:
    args = ["cc", "-D", "__FILENAME__=main.c", "-D", "KEEP=1", "src/main.c"]

    cleaned = BitcodeBuilder._sanitize_args(args, "main.c")

    assert cleaned == ["cc", '-D__FILENAME__="main.c"', "-D", "KEEP=1", "src/main.c"]


def test_sanitize_rewrites_vos_filename_define() -> None:
    args = [
        "cc",
        r"""-D__VOSFILENAME__='\"$(notdir""",
        r"""$(patsubst""",
        r"""\"%\",%,src/platform.c))\"'""",
        "src/platform.c",
    ]

    cleaned = BitcodeBuilder._sanitize_args(args, "src/platform.c")

    assert cleaned == ["cc", '-D__VOSFILENAME__="platform.c"', "src/platform.c"]
