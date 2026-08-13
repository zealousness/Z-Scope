import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.score_validator_replay_experiment import main as score_experiment_cli_main
from zscope.benchmarking.replay_bundle import write_validator_replay_bundle
from zscope.benchmarking.validator_experiment import (
    BALANCED_DEFAULT_EXPECTED_MAX_TOKENS,
    VALIDATOR_EXPERIMENT_SCHEMA_VERSION,
    ValidatorExperimentError,
    load_validator_replay_experiment,
    score_validator_replay_experiment,
    validate_validator_replay_experiment,
)
from zscope.benchmarking.validator_replay import (
    load_validator_arm_catalog,
    run_validator_replay,
    validator_arm,
    write_validator_replay_run,
)


IDENTITY = {
    "executor_sha256": "d" * 64,
    "model_spec_sha256": "e" * 64,
    "prompt_sha256": "f" * 64,
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _truth() -> dict:
    vulnerabilities = []
    for index in range(1, 137):
        vulnerabilities.append(
            {
                "id": f"RANGE-{index:03d}",
                "cwe": "CWE-120",
                "category": "buffer_overflow",
                "title": f"Unique overflow case {index:03d}",
                "file": f"src/case_{index:03d}.c",
                "function": f"vulnerable_{index:03d}",
                "line": 100 + index,
                "severity": "high",
                "keywords": [f"unique_{index:03d}", "copy"],
            }
        )
    return {
        "benchmark": "synthetic-validator-range",
        "version": 1,
        "total_vulnerabilities": 136,
        "vulnerabilities": vulnerabilities,
        "safe_entries": [],
    }


def _report() -> dict:
    states = []
    for index in range(1, 137):
        states.append(
            {
                "validation_cluster_uid": f"VAL-{index:03d}",
                "candidate_uid": f"CAND-{index:03d}",
                "occurrence_uids": [f"OCC-{index:03d}"],
                "entries": [f"entry_{index:03d}"],
                "terminal_disposition": "confirmed",
                "issue": {
                    "candidate_uid": f"CAND-{index:03d}",
                    "category": "buffer_overflow",
                    "cwe": "CWE-120",
                    "function": f"vulnerable_{index:03d}",
                    "file": f"src/case_{index:03d}.c",
                    "line": 100 + index,
                    "location": f"src/case_{index:03d}.c:{100 + index}",
                    "description": f"Unique overflow case {index:03d} reaches copy",
                    "evidence_pack": {
                        "positive_evidence": [f"unique_{index:03d} reaches copy"],
                    },
                },
            }
        )
    return {
        "run_manifest": {
            "source_tree_hash": "a" * 64,
            "config_hash": "b" * 64,
            "effective_rules_sha256": "c" * 64,
            "candidate_schema_version": "zscope.candidate.v3.3",
            "knowledge_db_version": "14",
        },
        "candidate_terminal_states": states,
    }


def _validator_result(call, verdict: str) -> dict:
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": call.candidate_uid,
        "validation_cluster_uid": call.validation_cluster_uid,
        "pass": call.validation_pass,
        "verdict": verdict,
        "reasoning": "Frozen evidence was evaluated under the selected arm contract.",
        "positive_evidence": ["frozen candidate location"],
        "negative_evidence": [],
        "evidence_refs": [],
        "blocking_negative_evidence": False,
        "missing_fact_request": None,
        "stop_reason": "decision_complete",
    }


def _executor(*, verified_count: int, total_tokens: int):
    def execute(call):
        index = int(call.candidate_uid.rsplit("-", 1)[-1])
        verdict = "verified" if index <= verified_count else "rejected"
        completion_tokens = 1
        prompt_tokens = total_tokens - completion_tokens
        return {
            "result": _validator_result(call, verdict),
            "usage": {
                "prompt_tokens": prompt_tokens,
                "cached_prompt_tokens": min(1, prompt_tokens),
                "completion_tokens": completion_tokens,
                "reasoning_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "tool_call_count": 0,
                "api_attempt_count": 1,
                "provider_reported": True,
            },
            "execution_identity": dict(IDENTITY),
        }

    return execute


def _write_run_matrix(
    directory: Path,
    *,
    bundle: dict,
    catalog: dict,
    counts=None,
    per_call_tokens=None,
) -> tuple[list[Path], dict[tuple[str, int], str]]:
    directory.mkdir(parents=True, exist_ok=True)
    selected_counts = counts or {"A": 111, "B": 112, "C": 111, "D": 112, "E": 112}
    selected_tokens = per_call_tokens or {"A": 10, "B": 8, "C": 5, "D": 7, "E": 12}
    paths = []
    hashes = {}
    for arm_id in "ABCDE":
        cap = 17_000_000 if arm_id == "E" else 12_000_000
        for trial_index in range(1, 6):
            result = run_validator_replay(
                bundle,
                validator_arm(catalog, arm_id),
                executor=_executor(
                    verified_count=selected_counts[arm_id],
                    total_tokens=selected_tokens[arm_id],
                ),
                execution_identity=IDENTITY,
                expected_bundle_sha256=bundle["bundle_sha256"],
                arm_catalog_sha256=catalog["catalog_sha256"],
                trial_index=trial_index,
                expected_total_tokens=cap,
                executor_trust=(
                    {
                        "mode": "trusted_oci_external",
                        "oci_evidence_sha256": "9" * 64,
                    }
                    if arm_id == "E"
                    else {
                        "mode": "builtin_provider",
                        "oci_evidence_sha256": "",
                    }
                ),
            )
            path = directory / f"arm-{arm_id}-trial-{trial_index}.json"
            write_validator_replay_run(path, result)
            paths.append(path)
            hashes[(arm_id, trial_index)] = result["run_sha256"]
    return paths, hashes


@pytest.fixture(scope="module")
def formal_matrix(tmp_path_factory):
    root = tmp_path_factory.mktemp("validator-experiment")
    truth_path = root / "truth.json"
    truth_path.write_text(
        json.dumps(_truth(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    bundle_path = root / "bundle.json"
    bundle = write_validator_replay_bundle(bundle_path, _report())
    catalog = load_validator_arm_catalog()
    run_paths, run_hashes = _write_run_matrix(root / "runs", bundle=bundle, catalog=catalog)
    return {
        "root": root,
        "truth_path": truth_path,
        "truth_sha256": _sha256_file(truth_path),
        "bundle_path": bundle_path,
        "bundle": bundle,
        "catalog": catalog,
        "run_paths": run_paths,
        "run_hashes": run_hashes,
    }


def _score(matrix, **overrides):
    arguments = {
        "bundle_path": matrix["bundle_path"],
        "run_paths": matrix["run_paths"],
        "truth_path": matrix["truth_path"],
        "expected_bundle_sha256": matrix["bundle"]["bundle_sha256"],
        "expected_truth_sha256": matrix["truth_sha256"],
        "expected_arm_catalog_sha256": matrix["catalog"]["catalog_sha256"],
        "expected_run_sha256s": matrix["run_hashes"],
        "cold_trials_attested": True,
    }
    arguments.update(overrides)
    return score_validator_replay_experiment(**arguments)


def test_formal_a_e_scorer_selects_lowest_token_arm_within_one_pp(formal_matrix) -> None:
    result = _score(formal_matrix)

    assert result["schema_version"] == VALIDATOR_EXPERIMENT_SCHEMA_VERSION
    assert result["release_eligible"] is False
    assert result["selection"]["selected_arm"] == "C"
    assert result["selection"]["eligible_arms"] == list("ABCDE")
    assert result["arms"]["A"]["metrics"]["median_confirmed_tp"] == 111
    assert result["arms"]["B"]["metrics"]["median_confirmed_tp"] == 112
    assert result["arms"]["C"]["metrics"]["true_positive_jaccard"] == 1.0
    assert result["arms"]["C"]["metrics"]["recall_range_pp"] == 0.0
    assert result["arms"]["C"]["metrics"]["provider_usage_coverage"] == 1.0
    assert result["arms"]["E"]["configured_cost_expectation_tokens"] == 17_000_000
    assert result["arms"]["E"]["gates"]["per_run_tokens"]["threshold"] == 12_000_000
    assert len(result["inputs"]["runs"]) == 25
    assert all(row["file_sha256"] for row in result["inputs"]["runs"])
    validate_validator_replay_experiment(result)


def test_arm_e_17m_execution_cap_is_not_a_12m_gate_exemption(formal_matrix, tmp_path: Path) -> None:
    high_paths, high_hashes = _write_run_matrix(
        tmp_path,
        bundle=formal_matrix["bundle"],
        catalog=formal_matrix["catalog"],
        counts={"A": 111, "B": 112, "C": 111, "D": 112, "E": 112},
        per_call_tokens={"A": 10, "B": 8, "C": 5, "D": 7, "E": 91_911},
    )
    base_paths = {
        (path.name.split("-")[1], int(path.stem.rsplit("-", 1)[-1])): path
        for path in formal_matrix["run_paths"]
    }
    base_hashes = dict(formal_matrix["run_hashes"])
    for path in high_paths:
        if path.name.startswith("arm-E-"):
            key = ("E", int(path.stem.rsplit("-", 1)[-1]))
            base_paths[key] = path
            base_hashes[key] = high_hashes[key]

    result = _score(
        formal_matrix,
        run_paths=[base_paths[key] for key in sorted(base_paths)],
        expected_run_sha256s=base_hashes,
    )

    arm_e = result["arms"]["E"]
    assert arm_e["metrics"]["max_tokens"] > BALANCED_DEFAULT_EXPECTED_MAX_TOKENS
    assert arm_e["gates"]["per_run_tokens"]["passed"] is False
    assert arm_e["passed"] is False
    assert "E" not in result["selection"]["eligible_arms"]


def test_scorer_fails_before_opening_truth_when_run_matrix_is_not_frozen(
    formal_matrix, tmp_path: Path
) -> None:
    nonexistent_truth = tmp_path / "must-not-be-opened.json"
    bad_hashes = dict(formal_matrix["run_hashes"])
    bad_hashes[("A", 1)] = "0" * 64

    with pytest.raises(ValidatorExperimentError, match="externally expected hash"):
        _score(
            formal_matrix,
            truth_path=nonexistent_truth,
            expected_truth_sha256="0" * 64,
            expected_run_sha256s=bad_hashes,
        )


def test_scorer_requires_explicit_cold_attestation_and_complete_hash_matrix(
    formal_matrix,
) -> None:
    with pytest.raises(ValidatorExperimentError, match="cold-trial attestation"):
        _score(formal_matrix, cold_trials_attested=False)

    incomplete = dict(formal_matrix["run_hashes"])
    incomplete.pop(("E", 5))
    with pytest.raises(ValidatorExperimentError, match="Arms A-E trials 1-5 exactly"):
        _score(formal_matrix, expected_run_sha256s=incomplete)


def test_experiment_result_loader_rejects_schema_drift_even_if_rehashed(
    formal_matrix, tmp_path: Path
) -> None:
    result = _score(formal_matrix)
    tampered = copy.deepcopy(result)
    tampered["arms"]["C"]["metrics"]["unknown_metric"] = 1
    from zscope.benchmarking.replay_bundle import canonical_json_sha256

    tampered["experiment_sha256"] = canonical_json_sha256(
        {key: value for key, value in tampered.items() if key != "experiment_sha256"}
    )
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")

    with pytest.raises(ValidatorExperimentError, match="metrics.*missing or unknown"):
        load_validator_replay_experiment(path)


def test_score_experiment_cli_writes_strict_artifact(formal_matrix, tmp_path: Path) -> None:
    output = tmp_path / "experiment.json"
    argv = [
        "--bundle",
        str(formal_matrix["bundle_path"]),
        "--expected-bundle-sha256",
        formal_matrix["bundle"]["bundle_sha256"],
        "--truth",
        str(formal_matrix["truth_path"]),
        "--expected-truth-sha256",
        formal_matrix["truth_sha256"],
        "--expected-arm-catalog-sha256",
        formal_matrix["catalog"]["catalog_sha256"],
        "--cold-trials-attested",
        "--output",
        str(output),
    ]
    for path in formal_matrix["run_paths"]:
        arm_id = path.name.split("-")[1]
        trial_index = int(path.stem.rsplit("-", 1)[-1])
        argv.extend(["--run", f"{arm_id}:{trial_index}:{path}"])
        argv.extend(
            [
                "--expected-run-sha256",
                f"{arm_id}:{trial_index}:{formal_matrix['run_hashes'][(arm_id, trial_index)]}",
            ]
        )

    assert score_experiment_cli_main(argv) == 0
    assert load_validator_replay_experiment(output)["selection"]["selected_arm"] == "C"
