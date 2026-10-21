from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from zscope.cli.wiki import main
from zscope.wiki.store.revision_store import WikiStore


FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def _config(root: Path, *, state_dir: str = "var/wiki") -> dict:
    return {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {
            "id": "configured-project",
            "root": str(root),
            "source_root": ".",
            "language": "c_cpp",
            "entry_discovery": {
                "enabled": True,
                "search_root": ".",
                "interface_files": ["include/**/*.h"],
                "max_entries": 20,
                "max_functions": 100,
            },
            "wiki": {
                "mode": "active",
                "state_dir": state_dir,
                "documents": {
                    "exclude": ["docs/api-limits.md"],
                    "classify": {
                        "explanatory": ["notes.md"],
                        "generated": ["generated-note.md"],
                    },
                },
                "max_file_bytes": 300,
                "max_files": 100,
                "max_total_bytes": 100000,
                "max_constraints": 8,
            },
        },
        "scan": {"task": ""},
        "indexing": {"backend": "regex"},
        "concurrency": {
            "entry_workers": 1,
            "validator_workers": 1,
            "investigator_workers": 1,
            "evidence_completion_workers": 1,
            "index_workers": 1,
            "svf_workers": 1,
            "llm_max_inflight": 1,
        },
    }


def test_wiki_cli_discover_build_status_and_query(tmp_path: Path) -> None:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, symlinks=True)
    runner = CliRunner()
    discovered = runner.invoke(main, ["--root", str(root), "discover"])
    assert discovered.exit_code == 0, discovered.output
    expected_count = 5 + int(not (root / "docs" / "outside.md").is_symlink())
    assert json.loads(discovered.output)["accepted"] == expected_count
    built = runner.invoke(main, ["--root", str(root), "build"])
    assert built.exit_code == 0, built.output
    status = runner.invoke(main, ["--root", str(root), "status"])
    assert status.exit_code == 0
    status_payload = json.loads(status.output)
    assert status_payload["available"] is True
    assert status_payload["active"]["revision_id"].startswith("wikirev_")
    query = runner.invoke(main, ["--root", str(root), "query", "--subject", "parse_byte", "--fact-kind", "value_range", "--file", "src/parser.c"])
    assert query.exit_code == 0, query.output
    assert json.loads(query.output)["resolution_mode"] == "source_fallback"
    rebuilt = runner.invoke(main, ["--root", str(root), "rebuild-index"])
    assert rebuilt.exit_code == 0, rebuilt.output
    assert json.loads(rebuilt.output)["sections"] > 0


def test_wiki_cli_config_closes_overrides_limits_and_query_budget(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, symlinks=True)
    shutil.rmtree(root / ".zscope_knowledge")
    (root / "notes.md").write_text("A short local note.\n", encoding="utf-8")
    (root / "generated-note.md").write_text(
        "A generated local note.\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "zscope.json"
    config_path.write_text(json.dumps(_config(root)), encoding="utf-8")
    runner = CliRunner()

    discovered = runner.invoke(main, ["--config", str(config_path), "discover"])
    assert discovered.exit_code == 0, discovered.output
    state = root / "var" / "wiki"
    manifest = json.loads((state / "source-manifest.json").read_text(encoding="utf-8"))
    assert manifest["project_id"] == "configured-project"
    assert "notes.md" in {item["relative_path"] for item in manifest["accepted"]}
    excluded = {item["relative_path"]: item["reason"] for item in manifest["excluded"]}
    assert excluded["README.md"] == "max_file_bytes_exceeded"
    assert excluded["docs/api-limits.md"] == "user_excluded_path"
    assert excluded["generated-note.md"] == "generated_override"
    assert not (root / ".zscope_knowledge").exists()

    query = runner.invoke(
        main,
        [
            "--config",
            str(config_path),
            "query",
            "--subject",
            "parse_byte",
            "--max-tokens",
            "600",
        ],
    )
    assert query.exit_code == 0, query.output
    assert json.loads(query.output)["selection"]["max_tokens"] == 600


def test_wiki_cli_custom_state_dir_does_not_change_its_own_manifest(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, symlinks=True)
    shutil.rmtree(root / ".zscope_knowledge")
    config_path = tmp_path / "zscope.json"
    config_path.write_text(json.dumps(_config(root)), encoding="utf-8")
    runner = CliRunner()

    first = runner.invoke(main, ["--config", str(config_path), "discover"])
    second = runner.invoke(main, ["--config", str(config_path), "discover"])

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert json.loads(first.output)["digest"] == json.loads(second.output)["digest"]


def test_wiki_cli_root_and_config_conflict_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    other = tmp_path / "other"
    root.mkdir()
    other.mkdir()
    config_path = tmp_path / "zscope.json"
    config_path.write_text(json.dumps(_config(root)), encoding="utf-8")

    result = CliRunner().invoke(
        main,
        ["--root", str(other), "--config", str(config_path), "status"],
    )

    assert result.exit_code == 2
    assert "conflicts with project.root" in result.output
    assert not (root / "var").exists()
    assert not (other / "var").exists()


def test_wiki_cli_read_commands_do_not_create_state(tmp_path: Path) -> None:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, symlinks=True)
    state = root / ".zscope_knowledge"
    shutil.rmtree(state)
    runner = CliRunner()

    status = runner.invoke(main, ["--root", str(root), "status"])
    assert status.exit_code == 0, status.output
    assert json.loads(status.output)["available"] is False
    assert not state.exists()

    linted = runner.invoke(main, ["--root", str(root), "lint"])
    assert linted.exit_code == 1
    assert not state.exists()

    queried = runner.invoke(
        main,
        ["--root", str(root), "query", "--subject", "parse_byte"],
    )
    assert queried.exit_code == 0, queried.output
    assert json.loads(queried.output)["resolution_mode"] == "source_fallback"
    assert not state.exists()


def test_wiki_cli_rollback_holds_writer_lock(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, symlinks=True)
    runner = CliRunner()
    built = runner.invoke(main, ["--root", str(root), "build"])
    assert built.exit_code == 0, built.output
    revision_id = json.loads(built.output)["revision_id"]
    original = WikiStore.rollback

    def checked(store, requested_revision_id):
        lock_path = root / ".zscope_knowledge" / "wiki" / "locks" / "compiler.lock"
        owner = json.loads(lock_path.read_text(encoding="utf-8"))
        assert owner["schema_version"] == "zscope.wiki-writer-lock.v1"
        return original(store, requested_revision_id)

    monkeypatch.setattr(WikiStore, "rollback", checked)
    rolled_back = runner.invoke(
        main,
        ["--root", str(root), "rollback", revision_id],
    )
    assert rolled_back.exit_code == 0, rolled_back.output
