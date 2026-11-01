"""Source-reviewed scan input is authoritative, even when discovery misses it."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from zscope.benchmarking.semantics import (
    REVIEW_SCHEMA,
    reviewed_entries,
    seed_document,
    source_hashes,
    validate_reviewed,
)
from zscope.benchmarking.semantic_scoring import score_discovery
from zscope.config.project_semantics import (
    canonical_digest,
    load_project_semantics,
    compiled_project_contracts,
)
from zscope.semantics.contracts import ApiContract


def row(name="allocate"):
    return {
        "id": "review:" + name,
        "primitive": False,
        "basis": "derived_wrapper",
        "status": "confirmed",
        "selector": {
            "kind": "function",
            "name": name,
            "file": "src/unit.c",
            "usr": "c:@F@" + name,
            "signature": "void *(unsigned long)",
        },
        "cases": [
            {
                "when": {
                    "op": "compare",
                    "left": {"kind": "return"},
                    "operator": "!=",
                    "right": {"kind": "literal", "value": None},
                },
                "effect": "applies",
            }
        ],
        "effects": [
            {
                "domain": "resource",
                "role": "allocator",
                "operation": "allocator",
                "carrier": {"root": "return"},
                "resource_family": "malloc",
                "strength": "must_under_guard",
            }
        ],
        "pairs": ["builtin:free"],
        "otherwise": "unknown",
        "derived_from": ["builtin:malloc"],
        "variants": [{"build_context_id": "original", "usr": "c:@F@" + name}],
        "review_reason": "Independently read the returned allocation in src/unit.c.",
    }


def test_reference_coverage_separates_absence_from_invalid_and_difference():
    reference = seed_document()
    reference["interfaces"] = [row(name) for name in ("matched", "invalid", "different", "absent")]
    output = deepcopy(reference)
    output["interfaces"].pop()
    output["interfaces"][1]["cases"] = [{"when": {"op": "true"}, "effect": "unknown"}]
    output["interfaces"][2]["effects"][0]["strength"] = "may"
    score = score_discovery(output, reference)
    assert score["reference_coverage_counts"] == {
        "matched": 1,
        "invalid_candidate": 1,
        "contract_difference": 1,
        "absent_effect": 1,
    }
    assert score["strict_recall"] == 0.25


def test_negated_comparison_is_a_mechanical_equivalence():
    reference = seed_document()
    reference["interfaces"] = [row()]
    output = deepcopy(reference)
    condition = output["interfaces"][0]["cases"][0]["when"]
    condition["operator"] = "=="
    output["interfaces"][0]["cases"][0]["when"] = {"op": "not", "item": condition}
    assert score_discovery(output, reference)["matched_assertions"] == 1


@pytest.mark.parametrize(
    "role,status", [("calloc", "contract_difference"), ("io_acquire", "absent_effect")]
)
def test_related_allocation_subtype_is_not_absence_or_a_strict_match(role, status):
    reference = seed_document()
    reference["interfaces"] = [row()]
    output = deepcopy(reference)
    effect = output["interfaces"][0]["effects"][0]
    effect.update(role=role, operation=role)
    score = score_discovery(output, reference)
    assert score["matched_assertions"] == 0
    assert score["strict_recall"] == 0
    assert score["reference_coverage"][0]["status"] == status


@pytest.mark.parametrize(
    "parameter,member,matched",
    [
        ("unsigned long", "", 1),
        ("const unsigned int", "", 1),
        ("long", "", 0),
        ("size_t", "", 0),
        ("unsigned long *", "", 0),
        ("unsigned long", "->signed_field", 0),
    ],
)
def test_zero_bound_equivalence_requires_explicit_unsigned_scalar_type(parameter, member, matched):
    reference = seed_document()
    reference["interfaces"] = [row()]
    r = reference["interfaces"][0]
    r["selector"]["signature"] = f"void *({parameter})"
    operand = {"kind": "argument", "index": 0}
    if member:
        operand["member_path"] = member
    positive = {
        "op": "compare",
        "left": operand,
        "operator": ">",
        "right": {"kind": "literal", "value": 0},
    }
    r["cases"] = [
        {"when": positive, "effect": "applies"},
        {"when": {"op": "not", "item": deepcopy(positive)}, "effect": "no_effect"},
    ]
    found = deepcopy(reference)
    found["interfaces"][0]["cases"][1]["when"] = {**deepcopy(positive), "operator": "=="}
    result = score_discovery(found, reference)
    assert result["matched_assertions"] == matched
    # Changing the return type/parameter type is still an identity mismatch.
    found["interfaces"][0]["selector"]["signature"] = "void *(int)"
    assert score_discovery(found, reference)["matched_assertions"] == 0


def reviewed(root):
    (root / "src").mkdir()
    (root / "src/unit.c").write_text("void *allocate(unsigned long n) { return malloc(n); }")
    (root / "CMakeLists.txt").write_text("project(unit C)")
    document = seed_document()
    document["interfaces"] = [row()]
    scope = {"positive_scope": "allocation result"}
    document["discovery_receipt"]["benchmark_review"] = {
        "schema": REVIEW_SCHEMA,
        "method": "independent_source_review",
        "sources": source_hashes(root),
        "scope": scope,
        "negative_contracts": [],
        "scope_digest": canonical_digest({"scope": scope, "negative_contracts": []}),
        "decisions_digest": canonical_digest(reviewed_entries(document)),
    }
    return document


@pytest.mark.parametrize(
    "change", ["condition", "carrier", "source", "decision", "scope", "negative", "method"]
)
def test_changed_source_review_cannot_silently_authorize_scan_or_score(tmp_path, change):
    document = reviewed(tmp_path)
    if change == "condition":
        document["interfaces"][0]["cases"][0]["when"] = {"op": "true"}
    elif change == "carrier":
        document["interfaces"][0]["effects"][0]["carrier"] = {"root": "argument", "index": 0}
    elif change == "source":
        (tmp_path / "src/new.c").write_text("void new_accessor(void) {}")
    elif change == "decision":
        document["interfaces"][0]["status"] = "rejected"
    elif change == "method":
        document["discovery_receipt"]["benchmark_review"]["method"] = "accept_discovery"
    else:
        review = document["discovery_receipt"]["benchmark_review"]
        review["scope" if change == "scope" else "negative_contracts"] = {}
    with pytest.raises(ValueError):
        validate_reviewed(document, tmp_path)


def test_source_reference_is_not_reduced_to_what_discovery_emits(tmp_path):
    reference = reviewed(tmp_path)
    reference["interfaces"].append(row("missed_output_allocator"))
    found = seed_document()
    found["interfaces"] = [row()]
    score = score_discovery(found, reference)
    assert score["expected_assertions"] == 2
    assert score["matched_assertions"] == 1
    assert score["strict_precision"] == 1
    assert score["strict_recall"] == 0.5
    assert score["missing"][0]["id"] == "review:missed_output_allocator"
    assert score_discovery(seed_document(), reference)["strict_recall"] == 0


def test_metadata_relocation_order_and_predicate_identity_do_not_change_meaning(tmp_path):
    reference = reviewed(tmp_path)
    found = deepcopy(reference)
    value = found["interfaces"][0]
    value.update(
        id="model:other-id", status="pending", evidence_ref="current", basis="expected_contract"
    )
    value["variants"][0]["build_context_id"] = "cold-native-build"
    value["selector"]["file"] = "/new/work/src/unit.c"
    value["selector"]["signature"] = "void* ( unsigned long )"
    condition = value["cases"][0]["when"]
    value["cases"][0]["when"] = {"op": "all", "items": [{"op": "true"}, condition, condition]}
    value["effects"][0]["carrier"].update(phase="post", dereference=0, members=[])
    assert score_discovery(found, reference)["strict_precision"] == 1


def test_executable_binding_alias_and_macro_display_signature_are_not_semantic_differences(
    tmp_path,
):
    reference = reviewed(tmp_path)
    row = reference["interfaces"][0]
    row["selector"].update(kind="macro", signature="")
    row["effects"][0]["protocol"] = {
        "transitions": [
            {
                "when": {"op": "true"},
                "actions": [
                    {"kind": "release", "object": {"kind": "argument", "argument_index": 0}}
                ],
            }
        ]
    }
    found = deepcopy(reference)
    found["interfaces"][0]["selector"]["signature"] = "#define allocate(p)"
    obj = found["interfaces"][0]["effects"][0]["protocol"]["transitions"][0]["actions"][0]["object"]
    obj["index"] = obj.pop("argument_index")
    assert score_discovery(found, reference)["matched_assertions"] == 1


@pytest.mark.parametrize(
    "change", ["carrier", "condition", "strength", "usr", "family", "protocol"]
)
def test_semantic_differences_remain_visible_not_automatically_false_positive(tmp_path, change):
    reference = reviewed(tmp_path)
    found = deepcopy(reference)
    item = found["interfaces"][0]
    effect = item["effects"][0]
    if change == "carrier":
        effect["carrier"] = {"root": "argument", "index": 1, "dereference": 1}
    elif change == "condition":
        item["cases"][0]["when"] = {"op": "true"}
    elif change == "strength":
        effect["strength"] = "may"
    elif change == "usr":
        item["selector"]["usr"] = "c:@F@wrong"
    elif change == "family":
        effect["resource_family"] = "fd"
    else:
        effect["protocol"] = {
            "transitions": [
                {
                    "when": {"op": "true"},
                    "actions": [
                        {"kind": "release", "object": {"kind": "argument", "argument_index": 0}}
                    ],
                }
            ]
        }
    score = score_discovery(found, reference)
    assert score["counts"]["mismatch"] == 1
    assert score["counts"]["incorrect"] == 0
    assert score["strict_recall"] == 0
    assert not score["semantic_accuracy_complete"]


def test_all_confirm_keeps_unknown_and_reports_document_unusable(tmp_path):
    reference = reviewed(tmp_path)
    found = deepcopy(reference)
    found["interfaces"][0]["status"] = "pending"
    found["interfaces"][0]["cases"] = [{"when": {"op": "true"}, "effect": "unknown"}]
    score = score_discovery(found, reference)
    assert score["counts"]["invalid"] == 1
    assert not score["all_confirm_document_valid"]
    assert len(score["missing"]) == 1
    assert found["interfaces"][0]["status"] == "pending"
    assert found["interfaces"][0]["cases"][0]["effect"] == "unknown"


def test_duplicate_assertions_cannot_inflate_recall(tmp_path):
    reference = reviewed(tmp_path)
    found = deepcopy(reference)
    duplicate = deepcopy(found["interfaces"][0])
    duplicate["id"] = "model:duplicate"
    found["interfaces"].append(duplicate)
    score = score_discovery(found, reference)
    assert score["matched_assertions"] == 1
    assert score["emitted_assertions"] == 1
    assert score["counts"]["duplicate"] == 1
    assert score["strict_recall"] == 1


def test_one_row_multiple_effects_matches_separate_source_obligations(tmp_path):
    reference = reviewed(tmp_path)
    other = deepcopy(reference["interfaces"][0])
    other["id"] = "review:member"
    other["effects"][0]["carrier"] = {"root": "return", "members": ["payload"]}
    reference["interfaces"].append(other)
    found = deepcopy(reference)
    found["interfaces"][0]["effects"].append(found["interfaces"].pop()["effects"][0])
    score = score_discovery(found, reference)
    assert score["expected_assertions"] == 2 and score["matched_assertions"] == 2


def test_malformed_duplicate_does_not_make_scoring_order_dependent(tmp_path):
    reference = reviewed(tmp_path)
    found = deepcopy(reference)
    bad = deepcopy(found["interfaces"][0])
    bad.update(id="invalid-copy", variants=[])
    found["interfaces"].insert(0, bad)
    first = score_discovery(found, reference)
    found["interfaces"].reverse()
    second = score_discovery(found, reference)
    assert first["counts"] == second["counts"]
    assert first["matched_assertions"] == 1
    assert not first["all_confirm_document_valid"]


def test_source_prohibition_and_unreviewed_new_output_are_distinct(tmp_path):
    reference = reviewed(tmp_path)
    bad = row("noop_free")
    bad["effects"][0]["role"] = "deallocator"
    reference["discovery_receipt"]["benchmark_review"]["negative_contracts"] = [
        {
            "selector": bad["selector"],
            "forbidden_roles": ["deallocator"],
            "resource_family": "malloc",
        }
    ]
    found = seed_document()
    found["interfaces"] = [bad, row("new_api")]
    score = score_discovery(found, reference)
    assert score["counts"]["incorrect"] == 1
    assert score["counts"]["unreviewed"] == 1
    assert score["precision_lower_bound"] == 0 and score["precision_upper_bound"] == 0.5


def test_shipped_source_reference_and_executable_semantics():
    root = Path(__file__).resolve().parents[1] / "test/range"
    document = validate_reviewed(load_project_semantics(root / "zscope.semantics.yaml"), root)
    assert not (root / "benchmark/interface_truth.json").exists()
    assert len(document["interfaces"]) == 56
    assert all(row["status"] == "confirmed" for row in document["interfaces"])
    assert score_discovery(document, document)["strict_recall"] == 1
    selected = {row["selector"]["name"]: row for row in document["interfaces"]}
    assert selected["_extract_payload"]["effects"][0]["carrier"]["index"] == 3
    assert selected["_serialize_task"]["effects"][0]["carrier"]["dereference"] == 1
    assert selected["_net_accept_connection"]["effects"][0]["resource_family"] == "descriptor"
    assert selected["_net_close_connection"]["effects"][0]["strength"] == "may"
    assert selected["_lock_read_wrapper"]["effects"][0]["protocol"]["lock_mode"] == "shared"
    build = selected["_lock_wrapper"]["variants"][0]["build_context_id"]
    contracts = compiled_project_contracts(document, build_context_id=build)
    locks = [
        ApiContract.from_row({"contract": c})
        for c in contracts
        if c["symbol"]["name"] == "_lock_wrapper"
    ]
    assert locks and all(c is not None and c.effects_trusted for c in locks)
    assert all(c.applicability(["object"], facts={"object": 1}) == "unknown" for c in locks)
    assert all(c.structural()["effect_authority"] == "may" for c in locks)
    from scripts.check_benchmark_hygiene import _semantic_input_errors

    assert _semantic_input_errors() == []


@pytest.mark.parametrize("mutate_reference", [False, True])
def test_discovery_uses_empty_input_and_scores_against_unchanged_scan_yaml_after_exit(
    tmp_path, monkeypatch, mutate_reference
):
    from zscope.benchmarking import semantic_runner as runner
    from zscope.benchmarking import semantic_scoring

    fixture = tmp_path / "fixture"
    fixture.mkdir()
    document = reviewed(fixture)
    reference_path = fixture / "zscope.semantics.yaml"
    reference_path.write_text(yaml.safe_dump(document))
    monkeypatch.setitem(runner.SPECS, "c_cpp", SimpleNamespace(fixture_root=fixture))
    monkeypatch.setattr(runner, "_require_llm_environment", lambda: None)
    monkeypatch.setattr(runner, "_tool_health", lambda _: {"ok": True, "checks": []})
    monkeypatch.setattr(
        runner, "_write_execution_config", lambda _, root, path, **kw: path.write_text("config")
    )
    monkeypatch.setattr(runner, "_build_fixture", lambda *a: None)
    monkeypatch.setattr(runner, "_record_range_link_target", lambda *a, **kw: None)
    completed = False

    def discover(argv, *, cwd, environment, log_path):
        nonlocal completed
        assert argv[-1] == "--discover-primitives"
        assert yaml.safe_load((cwd / "zscope.semantics.yaml").read_text()) == seed_document()
        assert not (cwd / "benchmark").exists()
        assert str(reference_path) not in argv
        found = seed_document()
        found["interfaces"] = [row()]
        (cwd / "zscope.semantics.yaml").write_text(yaml.safe_dump(found))
        if mutate_reference:
            reference_path.write_text("changed during model run")
        completed = True
        return 1.0

    def score(found, reference):
        assert completed
        assert reference == document
        return score_discovery(found, reference)

    monkeypatch.setattr(runner, "_run_command", discover)
    monkeypatch.setattr(semantic_scoring, "score_discovery", score)
    if mutate_reference:
        with pytest.raises(runner.BenchmarkError, match="changed during discovery"):
            runner.run_semantic_benchmark(
                output=tmp_path / "out", work_directory=tmp_path / "work", discovery=True
            )
    else:
        result = runner.run_semantic_benchmark(
            output=tmp_path / "out", work_directory=tmp_path / "work", discovery=True
        )
        assert result["completed"]
        assert json.loads((tmp_path / "out/score.json").read_text())["strict_recall"] == 1
        assert (
            tmp_path / "out/reference.semantics.yaml"
        ).read_bytes() == reference_path.read_bytes()


def test_public_prepare_and_discovery_commands():
    from zscope.cli.benchmark import _parser
    from zscope.benchmarking.runner import run_benchmark

    for depth in ("fast", "balanced", "deep"):
        args = _parser().parse_args(
            ["run", "--language", "c_cpp", "--mode", "prepare", "--scan-depth", depth]
        )
        result = run_benchmark(args.language, args.mode, scan_depth=depth, dry_run=True)
        assert not result["llm_called"] and "semantics-prepare" in result["stages"]
    assert _parser().parse_args(["semantics", "--output", "/tmp/exam"]).command == "semantics"
    from zscope.benchmarking.semantic_runner import run_semantic_benchmark

    preview = run_semantic_benchmark(output=Path("/tmp/unused"), discovery=True, dry_run=True)
    assert preview["llm_requested"] and not preview["llm_called"]


def test_model_completion_accepts_proposal_only_work_but_not_partial_errors():
    from zscope.benchmarking.semantic_runner import model_evaluation_complete

    full = {"eligible": 2, "reviewed": 2, "errors": 0}
    assert model_evaluation_complete({}, full, {"calls": 2})
    assert model_evaluation_complete(full, {}, {"calls": 2})
    assert not model_evaluation_complete({}, {}, {"calls": 2})
    assert not model_evaluation_complete({}, full, {"calls": 0})
    assert not model_evaluation_complete(full, {**full, "reviewed": 1}, {"calls": 4})
    assert not model_evaluation_complete(full, {**full, "errors": 1}, {"calls": 4})


def test_failed_trial_preserves_rebound_semantics_from_execution_copy(tmp_path, monkeypatch):
    from zscope.benchmarking import runner

    output = tmp_path / "artifacts"
    output.mkdir()

    def fail(spec, run_dir, run_number, *, workspace, **kwargs):
        state = workspace / "cache/project/.zscope_snapshots/semantics"
        state.mkdir(parents=True)
        (state / "effective.yaml").write_text("current evidence")
        raise RuntimeError("scan interrupted")

    monkeypatch.setattr(runner, "_run_trial_in_workspace", fail)
    with pytest.raises(RuntimeError, match="scan interrupted"):
        runner._run_trial(
            runner.SPECS["c_cpp"], output, 1, mode="trial", work_directory=tmp_path / "work"
        )
    assert (output / "semantic-preparation/effective.yaml").read_text() == "current evidence"
