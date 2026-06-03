import json
import subprocess
import hashlib
import shutil
from collections import Counter
from pathlib import Path

from zscope.retrieval.bitcode_scope import (
    BitcodeScopeConfig,
    BitcodeScopePlan,
    BitcodeSymbols,
    EntryBitcodeCluster,
    ExclusivePoolClassifier,
)
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


def _write_exclusive_pool_compile_commands(tmp_path: Path) -> tuple[Path, Path]:
    source_root = tmp_path / "project"
    normal_dir = source_root / "src" / "pool" / "normal"
    compat_dir = source_root / "src" / "pool" / "compat"
    normal_dir.mkdir(parents=True)
    compat_dir.mkdir(parents=True)
    (normal_dir / "A.c").write_text("int A(void) { return 1; }\n", encoding="utf-8")
    (compat_dir / "A.c").write_text("int A(void) { return 2; }\n", encoding="utf-8")
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text(
        json.dumps([
            {
                "directory": str(source_root),
                "command": "cc -c src/pool/normal/A.c",
                "file": "src/pool/normal/A.c",
            },
            {
                "directory": str(source_root),
                "command": "cc -c src/pool/compat/A.c",
                "file": "src/pool/compat/A.c",
            },
        ]),
        encoding="utf-8",
    )
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


def _fake_exclusive_pool_tools(monkeypatch, calls: list[str]) -> None:
    original_which = shutil.which

    def fake_run(cmd, *args, **kwargs):
        tool = Path(cmd[0]).name
        if tool in {"gclang", "get-bc", "llvm-link"}:
            calls.append(tool)
        if tool == "gclang":
            out_path = Path(cmd[cmd.index("-o") + 1])
            cwd = Path(kwargs.get("cwd") or ".")
            source_path = next(
                (
                    (Path(arg) if Path(arg).is_absolute() else cwd / Path(arg))
                    for arg in cmd
                    if Path(str(arg)).suffix.lower() == ".c"
                ),
                None,
            )
            source_text = str(source_path or "")
            out_path.write_text(f"object {source_text}\n", encoding="utf-8")
        elif tool == "get-bc":
            object_text = Path(cmd[1]).read_text(encoding="utf-8")
            Path(str(cmd[1]) + ".bc").write_text(f"bitcode {object_text}", encoding="utf-8")
        elif tool == "llvm-nm":
            bc_text = Path(cmd[-1]).read_text(encoding="utf-8")
            if "--undefined-only" in cmd:
                stdout = ""
            elif "normal" in bc_text or "compat" in bc_text:
                stdout = "T A\n"
            else:
                stdout = ""
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
        elif tool == "llvm-link":
            out_path = Path(cmd[cmd.index("-o") + 1])
            inputs = [Path(arg) for arg in cmd[cmd.index("-o") + 2:]]
            input_text = "\n".join(path.read_text(encoding="utf-8") for path in inputs)
            if "normal" in input_text and "compat" in input_text:
                raise subprocess.CalledProcessError(
                    1,
                    cmd,
                    stderr="error: Linking globals named 'A': symbol multiply defined!",
                )
            out_path.write_text("merged\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: name if Path(str(name)).name == "llvm-nm" else original_which(name),
    )


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


def test_saber_group_uses_old_style_entry_scope_variants(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_multi_compile_commands(tmp_path, 2)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    class FakeSelector:
        def __init__(self, *args, **kwargs):
            self.symbol_reader = self

        def read_symbols(self, _bc_path):
            return BitcodeSymbols()

        def cluster_entries(self, *, group_prefix, candidate_bcs, entries, **kwargs):
            plan = BitcodeScopePlan(
                group_name=f"{group_prefix}_1",
                mode="auto",
                entries=[str(entry) for entry in entries],
                selected_sources=[],
                selected_bcs=[str(candidate_bcs[0])],
            )
            return [
                EntryBitcodeCluster(
                    group_name=f"{group_prefix}_1",
                    entries=list(entries),
                    selected_bcs=[candidate_bcs[0]],
                    plan=plan,
                )
            ]

        def select(self, *, group_name, candidate_bcs, entries, **kwargs):
            return list(candidate_bcs), BitcodeScopePlan(
                group_name=group_name,
                mode="auto",
                entries=[str(entry) for entry in entries],
                selected_sources=[],
                selected_bcs=[str(path) for path in candidate_bcs],
            )

    monkeypatch.setattr("zscope.retrieval.build_llvm.EntryBitcodeSelector", FakeSelector)

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=output_dir,
        gclang_path="gclang",
        get_bc_path="get-bc",
        llvm_link_path="llvm-link",
    )
    original_variants = builder._exclusive_pool_link_variants
    variant_groups: list[str] = []

    def record_variant_group(**kwargs):
        variant_groups.append(str(kwargs["group_name"]))
        return original_variants(**kwargs)

    monkeypatch.setattr(builder, "_exclusive_pool_link_variants", record_variant_group)

    result = builder.build(
        scope_config=BitcodeScopeConfig(mode="auto"),
        entry_functions=["api"],
        knowledge_db=object(),
        project_root=source_root,
        auto_entry_clusters=True,
        saber_groups=True,
    )

    assert sorted(result) == ["entry_cluster_1", "saber:default"]
    assert variant_groups == ["default"]
    assert Counter(calls)["llvm-link"] == 2
    assert (output_dir / "merged_default.bc").exists()


def test_explicit_svf_group_can_be_entry_clustered(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_multi_compile_commands(tmp_path, 2)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    cluster_prefixes: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    class FakeSelector:
        def __init__(self, *args, **kwargs):
            self.symbol_reader = self

        def read_symbols(self, _bc_path):
            return BitcodeSymbols()

        def cluster_entries(self, *, group_prefix, candidate_bcs, entries, **kwargs):
            cluster_prefixes.append(group_prefix)
            plan = BitcodeScopePlan(
                group_name=f"{group_prefix}_1",
                mode="auto",
                entries=[str(entry) for entry in entries],
                selected_sources=[],
                selected_bcs=[str(path) for path in candidate_bcs],
            )
            return [
                EntryBitcodeCluster(
                    group_name=f"{group_prefix}_1",
                    entries=list(entries),
                    selected_bcs=list(candidate_bcs),
                    plan=plan,
                )
            ]

        def select(self, *args, **kwargs):  # pragma: no cover - should not be used here
            raise AssertionError("explicit groups should use entry clustering")

    monkeypatch.setattr("zscope.retrieval.build_llvm.EntryBitcodeSelector", FakeSelector)

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=output_dir,
        gclang_path="gclang",
        get_bc_path="get-bc",
        llvm_link_path="llvm-link",
    )
    result = builder.build(
        groups={"alpha": []},
        scope_config=BitcodeScopeConfig(mode="auto"),
        entry_functions=["api_alpha"],
        knowledge_db=object(),
        project_root=source_root,
        auto_entry_clusters=True,
    )

    assert cluster_prefixes == ["alpha__entry_cluster"]
    assert sorted(result) == ["alpha__entry_cluster_1"]
    assert (output_dir / "merged_alpha__entry_cluster_1.bc").exists()


def test_entry_cluster_links_directly_without_exclusive_pool_variants(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_multi_compile_commands(tmp_path, 2)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    _fake_bitcode_tools(monkeypatch, calls)

    class FakeSelector:
        def __init__(self, *args, **kwargs):
            self.symbol_reader = self

        def read_symbols(self, _bc_path):
            return BitcodeSymbols()

        def cluster_entries(self, *, group_prefix, candidate_bcs, entries, **kwargs):
            plan = BitcodeScopePlan(
                group_name=f"{group_prefix}_1",
                mode="auto",
                entries=[str(entry) for entry in entries],
                selected_sources=[],
                selected_bcs=[str(path) for path in candidate_bcs],
            )
            return [
                EntryBitcodeCluster(
                    group_name=f"{group_prefix}_1",
                    entries=list(entries),
                    selected_bcs=list(candidate_bcs),
                    plan=plan,
                )
            ]

    monkeypatch.setattr("zscope.retrieval.build_llvm.EntryBitcodeSelector", FakeSelector)

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=output_dir,
        gclang_path="gclang",
        get_bc_path="get-bc",
        llvm_link_path="llvm-link",
    )

    def fail_variants(**_kwargs):
        raise AssertionError("entry clusters should link directly")

    monkeypatch.setattr(builder, "_exclusive_pool_link_variants", fail_variants)

    result = builder.build(
        scope_config=BitcodeScopeConfig(
            mode="auto",
            exclusive_pools=[{"name": "pool", "paths": ["src/**"]}],
        ),
        entry_functions=["api"],
        knowledge_db=object(),
        project_root=source_root,
        auto_entry_clusters=True,
    )

    assert sorted(result) == ["entry_cluster_1"]
    assert (output_dir / "merged_entry_cluster_1.bc").exists()


def test_entry_cluster_layout_reused_when_fingerprint_unchanged(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_multi_compile_commands(tmp_path, 2)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    cluster_calls = {"count": 0}
    _fake_bitcode_tools(monkeypatch, calls)

    class FakeSelector:
        def __init__(self, *args, **kwargs):
            self.symbol_reader = self

        def read_symbols(self, _bc_path):
            return BitcodeSymbols()

        def cluster_entries(self, *, group_prefix, candidate_bcs, entries, **kwargs):
            cluster_calls["count"] += 1
            if cluster_calls["count"] > 1:
                raise AssertionError("cluster layout should have been reused")
            plan = BitcodeScopePlan(
                group_name=f"{group_prefix}_1",
                mode="auto",
                entries=[str(entry) for entry in entries],
                selected_sources=[],
                selected_bcs=[str(candidate_bcs[0])],
            )
            return [
                EntryBitcodeCluster(
                    group_name=f"{group_prefix}_1",
                    entries=list(entries),
                    selected_bcs=[candidate_bcs[0]],
                    plan=plan,
                )
            ]

        def select(self, *, group_name, candidate_bcs, entries, **kwargs):
            return list(candidate_bcs), BitcodeScopePlan(
                group_name=group_name,
                mode="auto",
                entries=[str(entry) for entry in entries],
                selected_sources=[],
                selected_bcs=[str(path) for path in candidate_bcs],
            )

    monkeypatch.setattr("zscope.retrieval.build_llvm.EntryBitcodeSelector", FakeSelector)

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=output_dir,
        gclang_path="gclang",
        get_bc_path="get-bc",
        llvm_link_path="llvm-link",
    )
    kwargs = dict(
        scope_config=BitcodeScopeConfig(mode="auto"),
        entry_functions=["api"],
        knowledge_db=object(),
        project_root=source_root,
        auto_entry_clusters=True,
    )

    first = builder.build(**kwargs)
    second = builder.build(**kwargs)

    assert sorted(first) == ["entry_cluster_1"]
    assert second == first
    assert cluster_calls["count"] == 1


def test_exclusive_pool_duplicate_symbols_split_link_variants(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_exclusive_pool_compile_commands(tmp_path)
    output_dir = tmp_path / ".zscope_bc"
    calls: list[str] = []
    _fake_exclusive_pool_tools(monkeypatch, calls)

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=output_dir,
        gclang_path="gclang",
        get_bc_path="get-bc",
        llvm_link_path="llvm-link",
    )
    result = builder.build(
        scope_config=BitcodeScopeConfig(
            mode="full",
            exclusive_pools=[
                {"name": "normal", "paths": ["src/pool/normal/**"]},
                {"name": "compat", "paths": ["src/pool/compat/**"]},
            ],
        )
    )

    assert sorted(result) == ["default__compat", "default__normal"]
    assert Counter(calls)["llvm-link"] == 2
    assert (output_dir / "merged_default__normal.bc").exists()
    assert (output_dir / "merged_default__compat.bc").exists()

    plan = json.loads((output_dir / "bitcode_scope_default.json").read_text(encoding="utf-8"))
    assert [item["symbol"] for item in plan["duplicate_symbols"]] == ["A"]
    assert sorted(item["exclusive_pool"] for item in plan["link_variants"]) == ["compat", "normal"]
    for variant in plan["link_variants"]:
        text = "\n".join(Path(path).read_text(encoding="utf-8") for path in variant["selected_bcs"])
        assert not ("normal" in text and "compat" in text)


def test_unclassified_duplicate_provider_becomes_default_variant_and_pulls_common_deps(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "project"
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text("[]", encoding="utf-8")
    normal_bc = tmp_path / "bc" / "normal.bc"
    compat_bc = tmp_path / "bc" / "compat.bc"
    common_bc = tmp_path / "bc" / "common.bc"
    for bc in (normal_bc, compat_bc, common_bc):
        bc.parent.mkdir(parents=True, exist_ok=True)
        bc.write_text(bc.stem, encoding="utf-8")

    class FakeSymbolReader:
        def read_symbols(self, bc_path: Path) -> BitcodeSymbols:
            if bc_path.name == "normal.bc":
                return BitcodeSymbols(
                    defined={"A"},
                    undefined={"helper"},
                    external_defined={"A"},
                )
            if bc_path.name == "compat.bc":
                return BitcodeSymbols(
                    defined={"A"},
                    undefined={"helper"},
                    external_defined={"A"},
                )
            if bc_path.name == "common.bc":
                return BitcodeSymbols(
                    defined={"helper"},
                    undefined=set(),
                    external_defined={"helper"},
                )
            return BitcodeSymbols()

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=tmp_path / ".zscope_bc",
    )
    bc_to_src = {
        normal_bc.resolve(): source_root / "ssp/src/ose/vfs/v_vfs/src/normal/v.c",
        compat_bc.resolve(): source_root / "ssp/src/ose/vfs/v_vfs/src/lite/v.c",
        common_bc.resolve(): source_root / "ssp/src/ose/vfs/common/helper.c",
    }
    builder._bc_to_src = dict(bc_to_src)

    variants, duplicates = builder._exclusive_pool_link_variants(
        group_name="default",
        bc_files=[normal_bc, compat_bc],
        all_bcs=[normal_bc, compat_bc, common_bc],
        bc_to_src=bc_to_src,
        pool_classifier=ExclusivePoolClassifier(
            source_root=source_root,
            project_root=source_root,
            pools=[{"name": "lite", "paths": [".*/lite/.*"]}],
        ),
        symbol_reader=FakeSymbolReader(),
    )

    assert [item["symbol"] for item in duplicates] == ["A"]
    assert [variant["exclusive_pool"] for variant in variants] == ["default", "lite"]

    by_pool = {variant["exclusive_pool"]: variant for variant in variants}
    default_names = {Path(path).name for path in by_pool["default"]["bc_files"]}
    lite_names = {Path(path).name for path in by_pool["lite"]["bc_files"]}
    assert default_names == {"normal.bc", "common.bc"}
    assert lite_names == {"compat.bc", "common.bc"}
    assert by_pool["default"]["dependency_closure_added"] == [common_bc.resolve().as_posix()]
    assert by_pool["lite"]["dependency_closure_added"] == [common_bc.resolve().as_posix()]


def test_shared_pool_dependency_is_reused_except_for_declared_conflict(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "project"
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text("[]", encoding="utf-8")
    normal_bc = tmp_path / "bc" / "normal.bc"
    lite_bc = tmp_path / "bc" / "lite.bc"
    liteos_bc = tmp_path / "bc" / "liteos.bc"
    generic_bc = tmp_path / "bc" / "generic.bc"
    for bc in (normal_bc, lite_bc, liteos_bc, generic_bc):
        bc.parent.mkdir(parents=True, exist_ok=True)
        bc.write_text(bc.stem, encoding="utf-8")

    class FakeSymbolReader:
        def read_symbols(self, bc_path: Path) -> BitcodeSymbols:
            if bc_path.name in {"normal.bc", "lite.bc", "liteos.bc"}:
                return BitcodeSymbols(
                    defined={"A"},
                    undefined={"helper"},
                    external_defined={"A"},
                )
            if bc_path.name == "generic.bc":
                return BitcodeSymbols(
                    defined={"helper"},
                    undefined=set(),
                    external_defined={"helper"},
                )
            return BitcodeSymbols()

    builder = BitcodeBuilder(
        source_root=source_root,
        compile_commands_path=compile_commands,
        output_dir=tmp_path / ".zscope_bc",
    )
    bc_to_src = {
        normal_bc.resolve(): source_root / "src/pool/normal/v.c",
        lite_bc.resolve(): source_root / "src/pool/lite/v.c",
        liteos_bc.resolve(): source_root / "src/pool/liteos/v.c",
        generic_bc.resolve(): source_root / "src/pool/generic/helper.c",
    }
    builder._bc_to_src = dict(bc_to_src)

    variants, _duplicates = builder._exclusive_pool_link_variants(
        group_name="default",
        bc_files=[normal_bc, lite_bc, liteos_bc],
        all_bcs=[normal_bc, lite_bc, liteos_bc, generic_bc],
        bc_to_src=bc_to_src,
        pool_classifier=ExclusivePoolClassifier(
            source_root=source_root,
            project_root=source_root,
            pools=[
                {"name": "normal", "paths": [".*/normal/.*"]},
                {"name": "lite", "paths": [".*/lite/.*"]},
                {"name": "liteos", "paths": [".*/liteos/.*"]},
            ],
            shared_pools=[
                {
                    "name": "generic",
                    "paths": [".*/generic/.*"],
                    "conflicts_with": ["liteos"],
                }
            ],
        ),
        symbol_reader=FakeSymbolReader(),
    )

    by_pool = {variant["exclusive_pool"]: variant for variant in variants}
    assert set(by_pool) == {"normal", "lite", "liteos"}
    assert {Path(path).name for path in by_pool["normal"]["bc_files"]} == {
        "normal.bc",
        "generic.bc",
    }
    assert {Path(path).name for path in by_pool["lite"]["bc_files"]} == {
        "lite.bc",
        "generic.bc",
    }
    assert {Path(path).name for path in by_pool["liteos"]["bc_files"]} == {"liteos.bc"}
    assert by_pool["normal"]["shared_pools"] == ["generic"]
    assert by_pool["lite"]["shared_pools"] == ["generic"]
    assert by_pool["liteos"]["shared_pools"] == []
    assert by_pool["liteos"]["excluded_conflicting_bcs"] == [generic_bc.resolve().as_posix()]


def test_path_can_have_exclusive_and_shared_pool_metadata(tmp_path: Path) -> None:
    source_root = tmp_path / "project"
    src = source_root / "src" / "pool" / "lite" / "generic" / "helper.c"
    classifier = ExclusivePoolClassifier(
        source_root=source_root,
        project_root=source_root,
        pools=[{"name": "lite", "paths": [".*/lite/.*"]}],
        shared_pools=[{"name": "generic", "paths": [".*/generic/.*"]}],
    )

    assert classifier.pool_for_source(src) == "lite"
    assert classifier.shared_pools_for_source(src) == ["generic"]


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
