"""S07-ORACLE: first executable test oracle for scan-demand equivalence (INC01-INC05).

The oracle executes the existing production shadow demand planner
(``plan_semantic_demand``, schema ``zscope.semantic-demand.shadow.v1``) and the
production incremental modeling path (``IncrementalSemanticModeling._plan_demand``
via ``GlobalModeler.run``) against the synthetic fixtures in
``tests/fixtures/scan_demand_equivalence/``. For the same current inputs it
verifies that independently produced "full" and "incremental" demand views have
no unexplained differences in:

- facts: per-symbol source hashes and context fingerprints;
- demand buckets: the per-symbol selected/deferred decision;
- pending obligations: row unknowns and unbound entries (stale hints, stale
  audit coverage, model-input-unavailable symbols);
- audit coverage: per-symbol coverage observations.

The oracle also proves the negative side on its own machinery: it rejects
views with fewer selected candidates, dropped pending obligations, merged
cross-build rows, and tampered or stale serialized plans.

Boundaries — explicitly untested, never reported as passing:

- No real LLM, native clang event, ValidationPipeline verdict bucket, dynamic
  receipt, or formal scorer is involved. ``RecordingAgent`` is a controlled
  response, so cost fields stay ``unknown``/null and are never measured.
- This is not INC05/RAPI10 acceptance: the shadow plan never replaces the full
  modeling schedule, and synthetic fixtures are not production events.
- The user-reserved task_0947f2854f branches (caller one-shot no-notify and
  limited timeout waits) are intentionally untouched by this module.
"""

from copy import deepcopy
from pathlib import Path
import json

import pytest

from test_global_modeler import FakeCodeIndex, RecordingAgent
from zscope.config.config import (
    AnalysisConfig,
    ConcurrencyConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.config.user_config_store import UserConfigStore
from zscope.orchestration.global_modeler import GlobalModeler
from zscope.orchestration.semantic_demand import (
    SCHEMA,
    SemanticDemandHint,
    plan_semantic_demand,
    source_hash,
)
from zscope.semantics.contracts import ApiContract, SymbolIdentity, digest
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.security_map import (
    AuditOccurrence,
    AuditUnit,
    CoverageKey,
    FunctionSecurityRecord,
    SecuritySemanticMap,
)
from zscope.snapshots.store import SnapshotStore

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "scan_demand_equivalence"
FIXTURE = json.loads((FIXTURE_DIR / "scenarios.json").read_text(encoding="utf-8"))

ROW_FIELDS = {
    "symbol",
    "source_hash",
    "context_fingerprint",
    "modeling_spec",
    "decision",
    "reasons",
    "unknowns",
    "semantic_status",
    "safety_status",
    "execution",
    "coverage",
}


# ---------------------------------------------------------------------------
# Fixture-driven scenario construction (inputs only; no truth labels).
# ---------------------------------------------------------------------------


def stage_state(stage=None):
    """Current synthetic program state after applying one staged mutation."""
    functions = {item["name"]: item for item in FIXTURE["functions"]}
    code = dict(FIXTURE["code"])
    if stage:
        spec = FIXTURE["stages"][stage]
        code.update(spec.get("code", {}))
        for name in spec.get("delete", []):
            code.pop(name, None)
    return {"functions": functions, "code": code}


def prefixed(code):
    """The line-numbered source form carried by production model inputs."""
    return (
        "\n".join(
            f"{number} | {line}" if line.strip() else line
            for number, line in enumerate(code.splitlines(), 1)
        )
        + "\n"
    )


def identity_of(name, build_context_id="", state=None):
    state = state or stage_state()
    fn = state["functions"][name]
    return SymbolIdentity.from_value(
        {
            "name": name,
            "file_path": fn["file"],
            "signature": fn["signature"],
            "build_context_id": build_context_id,
        }
    )


def context_for(state, name, code, build_context_id=""):
    fn = state["functions"][name]
    context = {
        "func_name": name,
        "file_path": fn["file"],
        "signature": fn["signature"],
        "code": code,
    }
    if build_context_id:
        context["build_context_id"] = build_context_id
    return context


def direct_plan(
    stage=None,
    *,
    hints=(),
    security_map=None,
    audit_units=(),
    unavailable=(),
    graph_truncated=False,
    contract_rows=(),
    context_overrides=None,
):
    """Call the production shadow planner directly on the fixture scenario."""
    state = stage_state(stage)
    contexts = {
        identity_of(name, state=state).key: context_for(state, name, code)
        for name, code in state["code"].items()
    }
    children = {
        identity_of(name, state=state).key: {
            identity_of(callee, state=state).key
            for callee in state["functions"][name]["callees"]
            if callee in state["code"]
        }
        for name in state["code"]
    }
    for key, extra in (context_overrides or {}).items():
        contexts[key] = {**contexts[key], **extra}
    registry = default_local_pattern_semantics().contracts
    for row in contract_rows:
        contract = ApiContract.from_row(row)
        if contract is not None:
            registry.add(contract)
    return plan_semantic_demand(
        contexts=contexts,
        children=children,
        components=[[key] for key in sorted(contexts)],
        registry=registry,
        spec=FIXTURE["spec"],
        hints=hints,
        security_map=security_map,
        audit_units=audit_units,
        unavailable=unavailable,
        graph_truncated=graph_truncated,
    )


def hint(hint_id, *, code_map, build_context_id=""):
    descriptor = next(item for item in FIXTURE["hints"] if item["id"] == hint_id)
    fn = next(item for item in FIXTURE["functions"] if item["name"] == descriptor["symbol"])
    return SemanticDemandHint(
        identity_of(fn["name"], build_context_id=build_context_id),
        source_hash({"code": code_map[fn["name"]]}),
        descriptor["kind"],
        tuple(descriptor["details"]),
    )


def security_map_for(code_map):
    """Build the synthetic audit map; its record binds to the given sources."""
    descriptor = FIXTURE["audit_units"][0]
    record = descriptor["record"]
    builds = FIXTURE["builds"]
    function_record = FunctionSecurityRecord(
        function_uid=record["function_uid"],
        index_name=record["index_name"],
        function_name=record["function_name"],
        file_path=record["file_path"],
        start_line=record["start_line"],
        end_line=record["end_line"],
        signature=record["signature"],
        code_hash=source_hash({"code": code_map[record["function_name"]]}),
        entry_identities=tuple(record["entry_identities"]),
        entry_paths=tuple(tuple(path) for path in record["entry_paths"]),
        callees=(),
        unresolved_callees=(),
        events=(),
        backend_coverage={},
    )
    unit = AuditUnit(
        unit_id=descriptor["unit_id"],
        unit_kind=descriptor["unit_kind"],
        fingerprint=descriptor["fingerprint"],
        risk_score=descriptor["risk_score"],
        risk_reasons=tuple(descriptor["risk_reasons"]),
        root_entries=tuple(record["entry_identities"]),
        member_functions=(record["function_uid"],),
        event_refs=(),
        claim_refs=(),
        unknown_refs=tuple(descriptor["unknown_refs"]),
        skill_families=tuple(descriptor["skill_families"]),
        backend_coverage={},
        candidate_desert=descriptor["candidate_desert"],
        coverage_keys=tuple(
            CoverageKey(
                "resource_lifecycle",
                record["function_uid"],
                item["object"],
                item["site"],
                builds[item["build"]] if item["build"] else None,
                item["scope_discriminator"],
            )
            for item in descriptor["coverage_keys"]
        ),
        occurrences=tuple(
            AuditOccurrence(
                item["entry_identity"], tuple(item["entry_path"]), tuple(item["event_refs"])
            )
            for item in descriptor["occurrences"]
        ),
    )
    security_map = SecuritySemanticMap(
        "synthetic-project",
        "synthetic-revision",
        "synthetic-profile",
        (function_record,),
        (),
        (),
        (unit,),
        {},
        {},
    )
    return security_map, unit


def staged_scenario_plan(stage=None):
    """The scenario with hints/audit map bound to the initial sources.

    When a stage mutates sources, the prior bindings must go visibly stale
    instead of silently following or disappearing.
    """
    initial = stage_state()
    security_map, unit = security_map_for(initial["code"])
    hints = tuple(hint(item["id"], code_map=initial["code"]) for item in FIXTURE["hints"])
    return direct_plan(stage=stage, hints=hints, security_map=security_map, audit_units=[unit])


def initial_scenario_plan():
    return staged_scenario_plan()


def cross_build_plan(hints=()):
    """Three compilation variants of one clean function, keyed by build."""
    state = stage_state()
    builds = FIXTURE["builds"]
    variants = {"": state["code"]["consume"], builds["primary"]: state["code"]["consume"]}
    variants[builds["secondary"]] = FIXTURE["build_variants"]["consume"]["secondary"]
    contexts = {}
    for build, code in variants.items():
        identity = identity_of("consume", build_context_id=build)
        contexts[identity.key] = context_for(state, "consume", code, build)
    return plan_semantic_demand(
        contexts=contexts,
        children={},
        components=[[key] for key in sorted(contexts)],
        registry=default_local_pattern_semantics().contracts,
        spec=FIXTURE["spec"],
        hints=hints,
    )


def generate_reference_fixture():
    """Regenerate the serialized reference plan (development helper, not a test)."""
    plan = initial_scenario_plan()
    path = FIXTURE_DIR / "stale_serialized_plan.json"
    path.write_text(
        json.dumps(plan, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {path}")


# ---------------------------------------------------------------------------
# Test-only oracle: field schema, normalization, and the equivalence verdict.
# ---------------------------------------------------------------------------


def validate_plan_schema(plan, label="plan"):
    """Reject malformed plans and any self-authorization in a serialized plan."""
    assert isinstance(plan, dict), f"{label}: plan is not an object"
    for field in (
        "schema_version",
        "mode",
        "changes_execution",
        "rows",
        "components",
        "selected",
        "deferred",
        "unknown",
        "unbound",
        "counts",
        "usage",
    ):
        assert field in plan, f"{label}: missing top-level field {field}"
    assert plan["schema_version"] == SCHEMA, f"{label}: unexpected schema"
    assert plan["mode"] == "shadow", f"{label}: mode must stay shadow"
    assert plan["changes_execution"] is False, f"{label}: plan changes execution"
    usage = plan["usage"]
    assert (
        isinstance(usage, dict) and usage.get("status") == "unknown"
    ), f"{label}: usage status must stay unknown"
    assert (
        usage.get("physical_attempts") is None and usage.get("tokens") is None
    ), f"{label}: costs must stay null instead of being fabricated"
    symbols = [row["symbol"] for row in plan["rows"]]
    assert len(symbols) == len(set(symbols)), f"{label}: duplicate row symbols (merged identities)"
    for row in plan["rows"]:
        assert (
            set(row) == ROW_FIELDS
        ), f"{label}: row field set differs: {sorted(set(row) ^ ROW_FIELDS)}"
        assert row["decision"] in {"selected", "deferred"}, f"{label}: unknown decision bucket"
        assert (
            row["semantic_status"] == "unknown" and row["safety_status"] == "unknown"
        ), f"{label}: {row['symbol']} claims a resolved status"
        assert (
            row["execution"] == "unchanged_full_schedule"
        ), f"{label}: {row['symbol']} changes execution"
    counts = plan["counts"]
    assert counts["planned"] == len(plan["rows"]), f"{label}: planned count mismatch"
    assert (
        counts["selected"]
        == len(plan["selected"])
        == sum(row["decision"] == "selected" for row in plan["rows"])
    ), f"{label}: selected count mismatch"
    assert (
        counts["deferred"]
        == len(plan["deferred"])
        == sum(row["decision"] == "deferred" for row in plan["rows"])
    ), f"{label}: deferred count mismatch"
    assert counts["unknown"] == len(plan["unknown"]), f"{label}: unknown count mismatch"
    assert set(plan["selected"]) | set(plan["deferred"]) == set(
        symbols
    ), f"{label}: selected/deferred do not partition the planned rows"
    assert not set(plan["selected"]) & set(
        plan["deferred"]
    ), f"{label}: a symbol is both selected and deferred"
    for entry in plan["unbound"]:
        assert "reason" in entry and (
            "symbol" in entry or "identity" in entry
        ), f"{label}: unbound entry lost its identity or reason"


def normalized_view(plan):
    """Comparable demand view: facts, buckets, pending obligations, coverage.

    ``usage`` is deliberately excluded: costs are retained separately as
    unknown/null and are never an equivalence dimension.
    """
    rows = {}
    for row in plan["rows"]:
        rows[row["symbol"]] = {
            "decision": row["decision"],
            "reasons": tuple(row["reasons"]),
            "unknowns": tuple(row["unknowns"]),
            "source_hash": row["source_hash"],
            "context_fingerprint": row["context_fingerprint"],
            "coverage": tuple(
                sorted((item["identity"], item["unit_id"]) for item in row["coverage"])
            ),
        }
    return {
        "rows": rows,
        "selected": tuple(plan["selected"]),
        "deferred": tuple(plan["deferred"]),
        "unknown": tuple(plan["unknown"]),
        "unbound": tuple(
            sorted(
                (entry.get("symbol", ""), entry.get("reason", ""), digest(entry))
                for entry in plan["unbound"]
            )
        ),
        "counts": dict(plan["counts"]),
    }


def _build_partition(view):
    """Group rows by (name, file, signature); builds must stay separate."""
    partition = {}
    for symbol in view["rows"]:
        identity = json.loads(symbol)
        base = (identity.get("name"), identity.get("file_path"), identity.get("signature"))
        partition.setdefault(base, set()).add(identity.get("build_context_id", ""))
    return {base: sorted(values) for base, values in sorted(partition.items())}


def assert_demand_equivalence(full, incremental, *, context=""):
    """Oracle: the same current input must yield no unexplained differences.

    ``full`` and ``incremental`` are two independently produced plans for the
    same current inputs. Explained (exempt) dimensions: the shadow ``usage``
    block (always unknown/null) and execution accounting, which lives in the
    modeler's ``actual_execution`` and is asserted separately. Everything else
    — row sets, decisions, reasons, facts, pending obligations, coverage, and
    the cross-build partition — must match, and obligations must not shrink.
    """
    validate_plan_schema(full, "full")
    validate_plan_schema(incremental, "incremental")
    left, right = normalized_view(full), normalized_view(incremental)
    differences = []
    missing = sorted(set(left["rows"]) - set(right["rows"]))
    extra = sorted(set(right["rows"]) - set(left["rows"]))
    if missing:
        differences.append(f"rows dropped from incremental (candidates/objects lost): {missing}")
    if extra:
        differences.append(f"rows invented by incremental: {extra}")
    for symbol in sorted(set(left["rows"]) & set(right["rows"])):
        for field in (
            "decision",
            "reasons",
            "unknowns",
            "source_hash",
            "context_fingerprint",
            "coverage",
        ):
            if left["rows"][symbol][field] != right["rows"][symbol][field]:
                differences.append(
                    f"row {symbol}: {field} differs: "
                    f"{left['rows'][symbol][field]!r} != {right['rows'][symbol][field]!r}"
                )
    lost_selected = sorted(set(left["selected"]) - set(right["selected"]))
    if lost_selected:
        differences.append(f"fewer selected candidates in incremental: {lost_selected}")
    lost_unknown = sorted(set(left["unknown"]) - set(right["unknown"]))
    if lost_unknown:
        differences.append(f"symbols lost from the unknown set: {lost_unknown}")
    lost_unbound = sorted(set(left["unbound"]) - set(right["unbound"]))
    if lost_unbound:
        differences.append(f"pending obligations (unbound entries) dropped: {lost_unbound}")
    if _build_partition(left) != _build_partition(right):
        differences.append(
            f"cross-build partition differs: {_build_partition(left)} != {_build_partition(right)}"
        )
    if left["counts"] != right["counts"]:
        differences.append(f"counts differ: {left['counts']} != {right['counts']}")
    assert not differences, (
        f"unexplained scan-demand differences ({context or 'same current input'}):\n  "
        + "\n  ".join(differences)
    )


def row_for(plan, name):
    return next(item for item in plan["rows"] if json.loads(item["symbol"])["name"] == name)


def view_rows_by_name(view):
    return {json.loads(symbol)["name"]: row for symbol, row in view["rows"].items()}


# ---------------------------------------------------------------------------
# Production modeler integration (IncrementalSemanticModeling._plan_demand).
# ---------------------------------------------------------------------------


class FixtureCodeIndex(FakeCodeIndex):
    """Synthetic index over the fixture program; tolerates deleted callees."""

    def __init__(self, state):
        self.impls = {}
        self.reload(state)

    def reload(self, state):
        impls = {}
        for name, code in state["code"].items():
            fn = state["functions"][name]
            impl = self._impl(name, list(fn["callees"]))
            impl["signature"] = fn["signature"]
            impl["code"] = prefixed(code)
            impls[name] = impl
        self.impls = impls

    def _callee_descriptors(self, impl):
        """Call edges from the caller's stored facts.

        Like the production index, an edge stays referenced by the caller even
        when the callee's implementation has disappeared from the index; the
        graph then reports it as unresolved instead of dropping it silently.
        """
        descriptors = []
        for callee in impl.get("callees", []):
            fn = next((item for item in FIXTURE["functions"] if item["name"] == callee), None)
            if fn is None:
                continue
            descriptors.append(
                {
                    "callee_index_name": f"{callee}@{fn['file']}:1-8",
                    "callsite_lines": [2],
                    "call_type": ["direct"],
                    "is_static": False,
                }
            )
        return descriptors

    def find_function_infos(self, func_name, file_path=""):
        matches = []
        for impl in self.impls.values():
            if func_name not in {impl["func_name"], impl["index_name"]}:
                continue
            if file_path and impl["file"] != file_path:
                continue
            matches.append(
                {
                    "function_name": impl["func_name"],
                    "file_path": impl["file"],
                    "index_name": impl["index_name"],
                    "start_line": impl["start_line"],
                    "end_line": impl["end_line"],
                    "signature": impl["signature"],
                    "is_static": impl["is_static"],
                    "is_macro": impl["is_macro"],
                    "project_callees": self._callee_descriptors(impl),
                    "external_callees": [],
                    "referenced_globals": [],
                    "referenced_macros": [],
                    "referenced_types": [],
                }
            )
        return matches


def fixture_entries():
    return [FunctionEntry(name) for name in FIXTURE["entries"]]


def _oracle_config(store_root: Path, project_root: Path) -> ZScopeConfig:
    """Like ``test_global_modeler._config``, but with a shared project root.

    The full and incremental modelers under comparison must scan the same
    project directory: the modeler embeds ``project_root`` in every planning
    context, so only the snapshot/user-config stores may differ.
    """
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(),
        analysis=AnalysisConfig(
            snapshot_dir=str(store_root / "snapshots"),
            user_config_db=str(store_root / "user-config"),
            max_premodel_depth=-1,
            max_premodel_callees=10,
            trivial_function_max_lines=0,
        ),
        project=ProjectConfig(project_root=project_root, source_root=project_root),
        concurrency=ConcurrencyConfig(),
    )


def oracle_modeler(
    store_root, project_root, state, calls, *, hints=(), security_map=None, audit_units=()
):
    config = _oracle_config(Path(store_root), Path(project_root))
    config.concurrency.entry_workers = 1
    config.concurrency.llm_max_inflight = 3
    config.analysis.semantic_model_demand_mode = "shadow"
    return GlobalModeler(
        config,
        FixtureCodeIndex(state),
        SnapshotStore(Path(config.analysis.snapshot_dir)),
        UserConfigStore(Path(config.analysis.user_config_db)),
        semantic_agent_factory=lambda: RecordingAgent(calls),
        demand_hints=hints,
        demand_security_map=security_map,
        demand_audit_units=audit_units,
    )


def latest_pass(modeler):
    passes = modeler.result.demand_plan["passes"]
    assert passes, "shadow demand plan has no passes"
    return passes[-1]


def _canonical_snapshot(snapshot):
    """Normalize the single observed cold/hot representation difference.

    Freshly modeled snapshots carry ``build_context_id: None`` (or omit it)
    while cache-restored ones carry ``""``; both denote an absent build
    context and ``SymbolIdentity.from_value`` maps them to the same identity.
    Nothing else is normalized — this is not a general snapshot scrubber.
    """
    value = dict(snapshot)
    value["build_context_id"] = value.get("build_context_id") or ""
    return value


def modeler_view(modeler):
    result = modeler.result
    return {
        "passes": [normalized_view(p) for p in result.demand_plan["passes"]],
        "snapshots": {
            key: digest(_canonical_snapshot(value)) for key, value in result.snapshots.items()
        },
        "contract_version": result.contract_version,
        "overlay": digest(result.overlay),
    }


def assert_modeler_equivalence(full, incremental, *, context=""):
    full_passes = full.result.demand_plan["passes"]
    incremental_passes = incremental.result.demand_plan["passes"]
    assert len(full_passes) == len(incremental_passes), f"{context}: planning pass count differs"
    for index, (left, right) in enumerate(zip(full_passes, incremental_passes)):
        assert_demand_equivalence(left, right, context=f"{context}: pass {index}")
    left, right = modeler_view(full), modeler_view(incremental)
    differences = []
    if set(left["snapshots"]) != set(right["snapshots"]):
        differences.append(
            f"snapshot symbols differ: {sorted(set(left['snapshots']) ^ set(right['snapshots']))}"
        )
    for key in sorted(set(left["snapshots"]) & set(right["snapshots"])):
        if left["snapshots"][key] != right["snapshots"][key]:
            differences.append(f"snapshot content differs for {key}")
    if left["contract_version"] != right["contract_version"]:
        differences.append("contract_version differs")
    if left["overlay"] != right["overlay"]:
        differences.append("semantic overlay differs")
    assert not differences, f"unexplained modeled-fact differences ({context}):\n  " + "\n  ".join(
        differences
    )


# ---------------------------------------------------------------------------
# Oracle self-verification: the oracle itself must reject degraded views.
# ---------------------------------------------------------------------------


def test_oracle_rejects_fewer_selected_candidates():
    plan = initial_scenario_plan()
    degraded = deepcopy(plan)
    victim = row_for(degraded, "helper")
    degraded["rows"].remove(victim)
    degraded["selected"].remove(victim["symbol"])
    degraded["unknown"].remove(victim["symbol"])
    degraded["counts"]["planned"] -= 1
    degraded["counts"]["selected"] -= 1
    degraded["counts"]["unknown"] -= 1
    with pytest.raises(AssertionError, match="rows dropped from incremental"):
        assert_demand_equivalence(plan, degraded)

    thinned = deepcopy(plan)
    target = row_for(thinned, "release_slot")
    target["coverage"] = target["coverage"][:1]
    with pytest.raises(AssertionError, match="coverage differs"):
        assert_demand_equivalence(plan, thinned)


def test_oracle_rejects_dropped_pending_obligations():
    plan = initial_scenario_plan()
    degraded = deepcopy(plan)
    target = row_for(degraded, "release_slot")
    target["unknowns"].remove("supplemental_context_unverified")
    with pytest.raises(AssertionError, match="unknowns differs"):
        assert_demand_equivalence(plan, degraded)

    initial = stage_state()
    stale = hint(
        "release-slot-document-conflict",
        code_map=stage_state("macro_and_target_change")["code"],
    )
    with_stale = direct_plan(hints=(stale,))
    assert any(entry["reason"] == "stale_or_unbound_hint" for entry in with_stale["unbound"])
    stripped = deepcopy(with_stale)
    stripped["unbound"] = [
        entry for entry in stripped["unbound"] if entry["reason"] != "stale_or_unbound_hint"
    ]
    stripped["counts"]["unbound"] = len(stripped["unbound"])
    with pytest.raises(AssertionError, match="pending obligations"):
        assert_demand_equivalence(with_stale, stripped)


def test_oracle_rejects_cross_build_row_merge():
    plan = cross_build_plan()
    secondary = FIXTURE["builds"]["secondary"]
    secondary_key = identity_of("consume", build_context_id=secondary).key
    merged = deepcopy(plan)
    merged["rows"] = [row for row in merged["rows"] if row["symbol"] != secondary_key]
    merged["deferred"].remove(secondary_key)
    merged["unknown"].remove(secondary_key)
    merged["counts"]["planned"] -= 1
    merged["counts"]["deferred"] -= 1
    merged["counts"]["unknown"] -= 1
    with pytest.raises(AssertionError, match="rows dropped from incremental"):
        assert_demand_equivalence(plan, merged)

    reidentified = deepcopy(plan)
    victim = next(row for row in reidentified["rows"] if row["symbol"] == secondary_key)
    victim["symbol"] = identity_of("consume").key
    with pytest.raises(AssertionError, match="duplicate row symbols"):
        validate_plan_schema(reidentified, "merged")


def test_oracle_rejects_tampered_serialized_plan():
    reference = json.loads((FIXTURE_DIR / "stale_serialized_plan.json").read_text(encoding="utf-8"))
    validate_plan_schema(reference, "reference")

    safety = deepcopy(reference)
    safety["rows"][0]["safety_status"] = "safe"
    with pytest.raises(AssertionError, match="claims a resolved status"):
        validate_plan_schema(safety, "tampered")

    execution = deepcopy(reference)
    execution["rows"][0]["execution"] = "reduced_schedule"
    with pytest.raises(AssertionError, match="changes execution"):
        validate_plan_schema(execution, "tampered")

    usage = deepcopy(reference)
    usage["usage"] = {"status": "measured", "physical_attempts": 1, "tokens": 12}
    with pytest.raises(AssertionError, match="usage status must stay unknown"):
        validate_plan_schema(usage, "tampered")

    costs = deepcopy(reference)
    costs["usage"] = {"status": "unknown", "physical_attempts": 1, "tokens": 12}
    with pytest.raises(AssertionError, match="costs must stay null"):
        validate_plan_schema(costs, "tampered")

    dropped = deepcopy(reference)
    dropped["rows"][0].pop("unknowns")
    with pytest.raises(AssertionError, match="row field set differs"):
        validate_plan_schema(dropped, "tampered")


# ---------------------------------------------------------------------------
# Direct real calls to the production shadow planner.
# ---------------------------------------------------------------------------


def test_same_current_input_plans_match_serialized_reference():
    first = initial_scenario_plan()
    second = initial_scenario_plan()
    assert_demand_equivalence(first, second, context="two independent planning invocations")
    reference = json.loads((FIXTURE_DIR / "stale_serialized_plan.json").read_text(encoding="utf-8"))
    assert first == reference
    assert reference["usage"] == {
        "status": "unknown",
        "physical_attempts": None,
        "tokens": None,
    }


def test_candidate_blind_exploration_keeps_no_candidate_objects_visible():
    plan = initial_scenario_plan()
    consume = row_for(plan, "consume")
    assert consume["decision"] == "selected"
    assert "candidate_missing_facts" in consume["reasons"]
    standalone = row_for(plan, "standalone")
    assert standalone["decision"] == "deferred"
    assert standalone["reasons"] == ["no_observed_demand"]
    assert "program_coverage_unavailable" in standalone["unknowns"]
    release_slot = row_for(plan, "release_slot")
    assert "audit_coverage_gap" in release_slot["reasons"]
    assert len(release_slot["coverage"]) == 3
    symbols = {row["symbol"] for row in plan["rows"]}
    assert set(plan["selected"]) | set(plan["deferred"]) == symbols
    assert plan["counts"]["planned"] == len(plan["rows"]) == 6


def test_unavailable_truncated_and_deleted_inputs_stay_visible():
    helper_key = identity_of("helper").key
    entry_key = identity_of("entry").key

    def truncated_plan():
        return direct_plan(
            stage="delete_helper",
            unavailable=[helper_key],
            graph_truncated=True,
            context_overrides={entry_key: {"source_truncated": True}},
        )

    plan = truncated_plan()
    assert helper_key not in {row["symbol"] for row in plan["rows"]}
    assert helper_key in plan["unknown"]
    assert {"symbol": helper_key, "reason": "model_input_unavailable"} in plan["unbound"]
    entry = row_for(plan, "entry")
    assert "coverage_gap" in entry["reasons"]
    assert "input_truncated" in entry["unknowns"]
    assert "call_graph_truncated" in entry["unknowns"]
    assert_demand_equivalence(plan, truncated_plan(), context="truncated and unavailable inputs")


def test_new_callback_dependency_invalidates_previous_deferral():
    before = direct_plan()
    before_row = row_for(before, "on_event")
    assert before_row["decision"] == "deferred"
    assert before_row["reasons"] == ["no_observed_demand"]

    after = direct_plan(stage="add_unknown_callback")
    after_row = row_for(after, "on_event")
    assert after_row["decision"] == "selected"
    assert "unknown_callback" in after_row["reasons"]
    assert "unknown_alias" in after_row["reasons"]
    assert after_row["source_hash"] != before_row["source_hash"]
    assert_demand_equivalence(
        after,
        direct_plan(stage="add_unknown_callback"),
        context="after a new unknown callback dependency",
    )
    with pytest.raises(AssertionError):
        assert_demand_equivalence(before, after)


def test_contract_and_source_changes_invalidate_bindings_without_dropping_rows():
    initial = stage_state()
    security_map, unit = security_map_for(initial["code"])
    hints = tuple(hint(item["id"], code_map=initial["code"]) for item in FIXTURE["hints"])
    without_contract = direct_plan(hints=hints, security_map=security_map, audit_units=[unit])

    with_contract = direct_plan(
        contract_rows=FIXTURE["manual_contract_rows"],
        hints=hints,
        security_map=security_map,
        audit_units=[unit],
    )
    assert "opaque_interface" in row_for(without_contract, "helper")["reasons"]
    assert "opaque_interface" not in row_for(with_contract, "helper")["reasons"]
    assert row_for(with_contract, "helper")["decision"] == "selected"
    assert {row["symbol"] for row in with_contract["rows"]} == {
        row["symbol"] for row in without_contract["rows"]
    }
    assert_demand_equivalence(
        with_contract,
        direct_plan(
            contract_rows=FIXTURE["manual_contract_rows"],
            hints=hints,
            security_map=security_map,
            audit_units=[unit],
        ),
        context="after a manual contract change",
    )

    changed = direct_plan(
        stage="macro_and_target_change",
        hints=hints,
        security_map=security_map,
        audit_units=[unit],
    )
    changed_row = row_for(changed, "release_slot")
    assert changed_row["source_hash"] != row_for(without_contract, "release_slot")["source_hash"]
    assert changed_row["coverage"] == []
    assert len([e for e in changed["unbound"] if e["reason"] == "stale_or_unbound_coverage"]) == 3
    assert len([e for e in changed["unbound"] if e["reason"] == "stale_or_unbound_hint"]) == 1
    assert {row["symbol"] for row in changed["rows"]} == {
        row["symbol"] for row in without_contract["rows"]
    }
    with pytest.raises(AssertionError):
        assert_demand_equivalence(without_contract, changed)


def test_cross_build_variants_stay_separated_and_hints_do_not_rebind():
    plan = cross_build_plan()
    builds = FIXTURE["builds"]
    state = stage_state()
    base_code = state["code"]["consume"]
    primary = identity_of("consume", build_context_id=builds["primary"])
    secondary = identity_of("consume", build_context_id=builds["secondary"])
    by_symbol = {row["symbol"]: row for row in plan["rows"]}
    assert len(by_symbol) == 3
    assert primary.key in by_symbol and secondary.key in by_symbol

    hinted = cross_build_plan(
        hints=(
            hint(
                "consume-candidate-blind",
                code_map={"consume": base_code},
                build_context_id=builds["primary"],
            ),
        )
    )
    hinted_rows = {row["symbol"]: row for row in hinted["rows"]}
    assert hinted_rows[primary.key]["decision"] == "selected"
    assert hinted_rows[primary.key]["reasons"] == ["candidate_missing_facts"]
    assert hinted_rows[secondary.key]["decision"] == "deferred"
    assert hinted_rows[secondary.key]["reasons"] == ["no_observed_demand"]

    misbound = cross_build_plan(
        hints=(
            SemanticDemandHint(
                secondary,
                source_hash({"code": base_code}),
                "candidate_missing_facts",
                ("synthetic misbound hint",),
            ),
        )
    )
    assert {
        "symbol": secondary.key,
        "reason": "stale_or_unbound_hint",
        "kind": "candidate_missing_facts",
    } in misbound["unbound"]
    assert_demand_equivalence(plan, cross_build_plan(), context="cross-build variants")


def test_stale_serialized_plan_cannot_replace_current_planning():
    reference = json.loads((FIXTURE_DIR / "stale_serialized_plan.json").read_text(encoding="utf-8"))
    fresh = initial_scenario_plan()
    assert fresh == reference
    validate_plan_schema(reference, "reference")
    changed = staged_scenario_plan("add_unknown_callback")
    with pytest.raises(AssertionError, match="on_event"):
        assert_demand_equivalence(
            reference, changed, context="stale serialized plan versus current inputs"
        )


# ---------------------------------------------------------------------------
# Production modeler integration: full versus incremental runs.
# ---------------------------------------------------------------------------


def test_incremental_rescan_reuses_cache_and_keeps_equivalent_demand(tmp_path):
    calls = []
    project = tmp_path / "project"
    state = stage_state()
    code_map = {name: prefixed(code) for name, code in state["code"].items()}
    security_map, unit = security_map_for(code_map)
    hints = tuple(hint(item["id"], code_map=code_map) for item in FIXTURE["hints"])
    modeler = oracle_modeler(
        tmp_path / "incremental",
        project,
        state,
        calls,
        hints=hints,
        security_map=security_map,
        audit_units=[unit],
    )
    cold = modeler.run(fixture_entries())
    # All functions produce snapshots. The trivially clean callee is served by
    # the production deterministic snapshot path without an agent call; the
    # entries and the opaque/indirect callers go through the recorded agent.
    assert len(modeler.result.snapshots) == len(state["code"])
    assert cold.modeled_functions == len(state["code"])
    assert cold.deterministic_snapshot_count + cold.llm_snapshot_count == len(state["code"])
    assert sorted(calls) == ["entry", "helper", "on_event", "release_slot", "standalone"]
    assert cold.total_context_tokens > 0
    calls.clear()
    hot = modeler.run(fixture_entries())
    assert calls == []
    assert hot.cache_hit_functions == len(state["code"])
    assert hot.total_context_tokens == 0

    demand = modeler.result.demand_plan
    assert len(demand["passes"]) == 1
    validate_plan_schema(demand["passes"][0], "hot incremental pass")
    assert demand["passes"][0]["usage"] == {
        "status": "unknown",
        "physical_attempts": None,
        "tokens": None,
    }
    actual = demand["actual_execution"]
    assert actual["usage_authority"] == "existing_accounting_only"
    assert actual["modeled_functions"] == 0
    assert actual["cache_hit_functions"] == len(state["code"])

    full = oracle_modeler(
        tmp_path / "full",
        project,
        state,
        [],
        hints=hints,
        security_map=security_map,
        audit_units=[unit],
    )
    full.run(fixture_entries())
    assert_modeler_equivalence(
        full, modeler, context="independent full versus hot incremental rescan"
    )


def test_staged_mutations_keep_full_and_incremental_equivalent(tmp_path):
    calls = []
    project = tmp_path / "project"
    initial = stage_state()
    code_map = {name: prefixed(code) for name, code in initial["code"].items()}
    security_map, unit = security_map_for(code_map)
    hints = tuple(hint(item["id"], code_map=code_map) for item in FIXTURE["hints"])
    modeler = oracle_modeler(
        tmp_path / "incremental",
        project,
        initial,
        calls,
        hints=hints,
        security_map=security_map,
        audit_units=[unit],
    )
    modeler.run(fixture_entries())
    initial_view = modeler_view(modeler)
    initial_rows = view_rows_by_name(initial_view["passes"][-1])
    assert initial_rows["on_event"]["decision"] == "deferred"
    initial_release_hash = initial_rows["release_slot"]["source_hash"]

    for stage in (
        "add_unknown_callback",
        "macro_and_target_change",
        "delete_helper",
        "restore",
    ):
        state = stage_state(stage)
        modeler.code_index.reload(state)
        calls.clear()
        modeler.run(fixture_entries())
        full = oracle_modeler(
            tmp_path / f"full-{stage}",
            project,
            state,
            [],
            hints=hints,
            security_map=security_map,
            audit_units=[unit],
        )
        full.run(fixture_entries())
        assert_modeler_equivalence(full, modeler, context=f"stage {stage}")

        rows = view_rows_by_name(normalized_view(latest_pass(modeler)))
        if stage == "add_unknown_callback":
            assert rows["on_event"]["decision"] == "selected"
            assert "unknown_callback" in rows["on_event"]["reasons"]
        elif stage == "macro_and_target_change":
            assert rows["release_slot"]["source_hash"] != initial_release_hash
            assert rows["release_slot"]["coverage"] == ()
            reasons = [reason for _, reason, _ in normalized_view(latest_pass(modeler))["unbound"]]
            assert reasons.count("stale_or_unbound_coverage") == 3
            assert reasons.count("stale_or_unbound_hint") == 1
        elif stage == "delete_helper":
            assert "helper" not in rows
            pass_view = normalized_view(latest_pass(modeler))
            # The unresolved reference keeps its raw spelling (index name),
            # exactly like a missing entry; it must stay visible, not vanish.
            assert any(
                json.loads(symbol)["name"].split("@", 1)[0] == "helper"
                for symbol in pass_view["unknown"]
            )
            assert any(
                reason == "model_input_unavailable"
                and json.loads(symbol)["name"].split("@", 1)[0] == "helper"
                for symbol, reason, _ in pass_view["unbound"]
            )
        else:
            assert modeler_view(modeler) == initial_view
