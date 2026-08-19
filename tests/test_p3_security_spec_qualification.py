from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "qualify_p3_security_specs.py"


def _module():
    spec = importlib.util.spec_from_file_location("qualify_p3_security_specs", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p3_blind_corpus_qualification_passes_all_thresholds() -> None:
    result = _module().qualify(ROOT / "tests" / "fixtures" / "p3_security_specs")
    metrics = result["qualification"]["metrics"]

    assert result["case_count"] == 143
    assert result["positive_case_count"] == 104
    assert result["safe_case_count"] == 39
    assert result["compiled_spec_count"] == 104
    assert result["compilation_mode"] == "authoritative"
    assert metrics == {
        "case_count": 143,
        "key_contract_recall": 1.0,
        "positive_unsupported_rate": 0.0,
        "safe_false_activation_count": 0,
        "evidence_resolution_rate": 1.0,
        "second_scan_llm_reduction": 1.0,
    }


def test_p3_product_miner_does_not_read_expected_contract_file() -> None:
    source = (ROOT / "zscope" / "semantics" / "security_specs" / "miner.py").read_text(
        encoding="utf-8"
    )
    assert "expected-contracts" not in source
    assert "tests/fixtures" not in source


def test_p3_corpus_manifest_binds_all_input_files() -> None:
    root = ROOT / "tests" / "fixtures" / "p3_security_specs"
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["case_expansion"]["case_count"] == 143
    for relative, expected in manifest["file_hashes"].items():
        actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        assert actual == expected
