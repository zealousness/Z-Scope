from zscope.retrieval.build_llvm import BitcodeBuilder


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
