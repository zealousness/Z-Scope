import json

from zscope.config.config import ConfigLoader, SemanticDedupConfig


def _base_config(tmp_path):
    return {
        "llms": {
            "default": {
                "model": "unit-model",
                "api_key": "unit-key",
            }
        },
        "project": {
            "root": str(tmp_path),
            "source_root": str(tmp_path),
        },
    }


def test_semantic_dedup_config_defaults_to_llm_disabled() -> None:
    cfg = SemanticDedupConfig()

    assert cfg.enabled is True
    assert cfg.llm_enabled is False


def test_config_loader_defaults_llm_semantic_dedup_to_disabled(tmp_path) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(_base_config(tmp_path)), encoding="utf-8")

    cfg = ConfigLoader.load(str(path))

    assert cfg.reporting.semantic_dedup.enabled is True
    assert cfg.reporting.semantic_dedup.llm_enabled is False


def test_config_loader_allows_disabling_llm_semantic_dedup(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["reporting"] = {"semantic_dedup": {"llm_enabled": False}}
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    cfg = ConfigLoader.load(str(path))

    assert cfg.reporting.semantic_dedup.enabled is True
    assert cfg.reporting.semantic_dedup.llm_enabled is False


def test_config_loader_allows_enabling_llm_semantic_dedup(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["reporting"] = {"semantic_dedup": {"llm_enabled": True}}
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    cfg = ConfigLoader.load(str(path))

    assert cfg.reporting.semantic_dedup.enabled is True
    assert cfg.reporting.semantic_dedup.llm_enabled is True


def test_config_loader_reads_global_model_flag(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["analysis"] = {"enable_global_model": True}
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    cfg = ConfigLoader.load(str(path))

    assert cfg.analysis.enable_global_model is True


def test_config_loader_reads_independent_v31_fact_rollout_flags(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["analysis"] = {
        "decision_fact_graph_v1": True,
        "security_obligation_v1": True,
        "deterministic_prevalidation_v2": True,
        "decision_context_v31": True,
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    cfg = ConfigLoader.load(str(path))

    assert cfg.analysis.decision_fact_graph_v1 is True
    assert cfg.analysis.security_obligation_v1 is True
    assert cfg.analysis.deterministic_prevalidation_v2 is True
    assert cfg.analysis.decision_context_v31 is True


def test_config_loader_reads_independent_v32_evidence_closure_flags(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["analysis"] = {
        "project_deterministic_fact_pass_v1": True,
        "proof_providers_v11": True,
        "decision_context_v32": True,
        "structured_candidate_promotion_v1": True,
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    cfg = ConfigLoader.load(str(path))

    assert cfg.analysis.project_deterministic_fact_pass_v1 is True
    assert cfg.analysis.proof_providers_v11 is True
    assert cfg.analysis.decision_context_v32 is True
    assert cfg.analysis.structured_candidate_promotion_v1 is True


def test_config_loader_reads_independent_v33_release_flags(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["analysis"] = {
        "proof_providers_v12": True,
        "decision_context_v33": True,
        "finding_root_v1": True,
        "validator_evidence_slice_v2": True,
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    cfg = ConfigLoader.load(str(path))

    assert cfg.analysis.proof_providers_v12 is True
    assert cfg.analysis.decision_context_v33 is True
    assert cfg.analysis.finding_root_v1 is True
    assert cfg.analysis.validator_evidence_slice_v2 is True
