from dataclasses import replace

import pytest

from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from test_wrapper_contract_compiler import context, compile_all, publish


@pytest.mark.parametrize(
    "api",
    ["pthread_mutex_lock", "pthread_rwlock_rdlock", "pthread_mutex_unlock", "free", "realloc"],
)
def test_reviewed_may_effect_never_becomes_certain_under_a_satisfied_guard(api):
    from zscope.semantics.contracts import CONTRACT_COMPILER_VERSION
    from zscope.semantics.defaults import default_local_pattern_semantics

    registry = default_local_pattern_semantics().contracts
    (base,) = registry.find(api)
    possible = replace(
        base,
        source="inferred:project_semantics:possible",
        verification={
            "method": "source_composition",
            "compiler_version": CONTRACT_COMPILER_VERSION,
            "source_hash": "current-source",
            "identity_verified": True,
            "authority": "native_current",
            "effect_strength": "may",
        },
    )
    arguments = ["object", "8"]
    returned = "new_object" if api == "realloc" else "0"
    facts = {"object": 1, "new_object": 2}
    assert base.applicability(arguments, returned, facts) == "applies"
    if api == "realloc":
        assert registry.allocation_extent(api, arguments) == "8"
    assert possible.effects_trusted  # usable as a possible candidate signal
    assert possible.applicability(arguments, returned, facts) == "unknown"
    assert possible.structural()["effect_authority"] == "may"
    registry.add(possible)
    transitions = registry.resolved_transitions(api, arguments, returned, facts=facts)
    assert all(event["applicability"] != "applies" for event in transitions)
    assert registry.allocation_extent(api, arguments) == ""


@pytest.mark.parametrize(
    "name,mode",
    [
        ("pthread_mutex_lock", "exclusive"),
        ("pthread_mutex_trylock", "exclusive"),
        ("pthread_mutex_timedlock", "exclusive"),
        ("pthread_mutex_clocklock", "exclusive"),
        ("pthread_rwlock_rdlock", "shared"),
        ("pthread_rwlock_tryrdlock", "shared"),
        ("pthread_rwlock_timedrdlock", "shared"),
        ("pthread_rwlock_wrlock", "exclusive"),
        ("pthread_rwlock_trywrlock", "exclusive"),
        ("pthread_rwlock_timedwrlock", "exclusive"),
        ("pthread_spin_lock", "exclusive"),
        ("pthread_spin_trylock", "exclusive"),
    ],
)
def test_standard_mode_and_status_reach_consumer(name, mode):
    registry = default_local_pattern_semantics().contracts
    for value, expected in [(0, "applies"), (16, "does_not_apply")]:
        (event,) = registry.match_call(
            name, "lock", ["&a.guard"], "rc", facts={"rc": value, "EOWNERDEAD": 130}
        )
        assert event.lock_mode == mode and event.applicability == expected
        assert event.object == "&a.guard"
        (action,) = event.transitions[0]["actions"]
        assert action == {"kind": "acquire", "object": "&a.guard", "lock_mode": mode}
        assert event.to_dict()["lock_mode"] == mode
    (unknown,) = registry.match_call(name, "lock", ["&b.guard"])
    assert unknown.applicability == "unknown" and unknown.object != event.object


@pytest.mark.parametrize(
    "mode,primitive",
    [("shared", "pthread_rwlock_tryrdlock"), ("exclusive", "pthread_rwlock_wrlock")],
)
def test_transparent_wrappers_reload_modes_and_conditions(tmp_path, mode, primitive):
    snapshots = compile_all(
        [
            context("alpha", f"int alpha(void *m) {{ return {primitive}(m); }}"),
            context("beta", "int beta(void *m) { return alpha(m); }"),
            context("omega", "int omega(void *m) { return pthread_rwlock_unlock(m); }"),
        ]
    )
    _, semantics, overlay = publish(tmp_path, snapshots)
    for name in ("alpha", "beta"):
        (contract,) = semantics.contracts.find(name, "lock")
        assert contract.effects_trusted and contract.lock_mode == mode
        assert contract.applicability(["&a.guard"], "rc", {"rc": 16}) == "does_not_apply"
        (event,) = semantics.contracts.match_call(name, "lock", ["&a.guard"], "0")
        assert event.lock_mode == mode and event.applicability == "applies"
        assert event.transitions[0]["actions"][0]["lock_mode"] == mode
        assert semantics.contracts.allows(name, "omega")
    assert overlay["api_contracts"]


def test_robust_and_wait_do_not_lose_acquisition_or_interruption():
    registry = default_local_pattern_semantics().contracts
    (event,) = registry.match_call(
        "pthread_mutex_trylock", "lock", ["&m"], "rc", facts={"rc": 130, "EOWNERDEAD": 130}
    )
    assert event.applicability == "applies" and event.lock_mode == "exclusive"
    (event,) = registry.match_call(
        "pthread_cond_timedwait",
        "lock_wait",
        ["&cv", "&m", "&time"],
        "rc",
        facts={"rc": 110, "ETIMEDOUT": 110, "EOWNERDEAD": 130},
    )
    assert event.applicability == "applies"
    assert [a["kind"] for a in event.transitions[0]["actions"]] == ["release", "acquire"]
    assert event.transitions[0]["actions"][1]["lock_mode"] == "exclusive"
    assert event.lock_mode == "unknown"  # a wait is not continuous protection


def test_unverified_recovery_cannot_regain_authority_through_transition():
    registry = default_local_pattern_semantics().contracts
    (base,) = registry.find("pthread_mutex_lock", "lock")
    # The wrapper verifier may prove only return==0 while keeping recovery
    # on EOWNERDEAD unresolved. Its inherited actions must obey that gap.
    from zscope.semantics.contract_conditions import compare

    registry.add(
        replace(
            base,
            symbol=replace(base.symbol, name="alpha"),
            effect_cases=[
                {"when": compare({"kind": "return"}, "==", 0), "effect": "applies"},
                {"when": compare({"kind": "return"}, "!=", 0), "effect": "unknown"},
            ],
        )
    )
    (event,) = registry.match_call("alpha", "lock", ["&m"], "130", facts={"EOWNERDEAD": 130})
    assert event.applicability == "unknown"
    assert event.transitions[0]["applicability"] == "unknown"


@pytest.mark.parametrize("mode", [None, "unknown", "shared", "bogus", [], {"mode": "exclusive"}, 1])
def test_legacy_text_provider_cannot_erase_write_with_weak_mode(mode):
    lock = ApiContract.from_row(
        {
            "symbol_name": "alpha",
            "kind": "lock",
            "pair": ["omega"],
            "contract": {"protocol": {"lock_mode": mode}},
        }
    )
    unlock = ApiContract.from_row({"symbol_name": "omega", "kind": "unlock"})
    issue = {
        "rule": "clang_cfg_unsynchronized_shared_state",
        "source": "shared",
        "sink": "shared++;",
    }
    # Use a real registered source-lockset rule.
    issue["rule"] = sorted(EvidenceCompletionQueue._SOURCE_LOCKSET_RULES)[0]
    pack = {
        "function_context": {"code": "void f(void) {\n alpha(&m);\n shared++;\n omega(&m);\n}"},
        "semantic_contracts": {"api_contracts": [lock.to_dict(), unlock.to_dict()]},
    }
    assert EvidenceCompletionQueue._source_lockset_dominance_proof(issue, pack) is None
    unverified = replace(lock, source="inferred:model", protocol={"lock_mode": "exclusive"})
    assert unverified.lock_mode == "unknown"


@pytest.mark.parametrize(
    "mode,expected", [("shared", True), ("unknown", True), ("exclusive", False)]
)
@pytest.mark.parametrize("engine", ["regex", "clang"])
def test_candidate_modes_default_off_and_explicit_enable(mode, expected, engine):
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.rules.catalog import RuleCatalog, EffectiveRuleSet

    semantics = default_local_pattern_semantics()
    semantics.merge_overlay(
        {
            "api_contracts": [
                {
                    "symbol": {"name": "alpha"},
                    "role": "lock",
                    "pairs": ["omega"],
                    "carrier": {"kind": "argument", "argument_index": 0},
                    "source": "user",
                    "protocol": {"lock_mode": mode},
                },
                {"symbol": {"name": "omega"}, "role": "unlock", "source": "user"},
            ]
        }
    )
    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    rule = ("clang_cfg_" if engine == "clang" else "") + "unsynchronized_shared_flag_or_counter"
    catalog = RuleCatalog.builtin()
    descriptor = catalog.get(rule)
    assert descriptor.revision == 10 and not descriptor.default_enabled
    code = "void f(void) {\n alpha(&m);\n shared++;\n omega(&m);\n}"
    for enabled, disabled, emits in [
        ((), (), False),
        ((rule,), (), expected),
        ((rule,), (rule,), False),
    ]:
        policy = EffectiveRuleSet.build(
            catalog, language="c_cpp", backend="unified", enabled_ids=enabled, disabled_ids=disabled
        )
        generator = cls(semantics=semantics, rule_policy=policy.policy)
        issues = generator.generate_issues("f", code, "a.c")
        assert any(i.get("rule") == rule for i in issues) == emits


@pytest.mark.parametrize(
    "interruption", ["pthread_cond_wait(&cv,&m);", "pthread_rwlock_unlock(&m);"]
)
def test_unknown_unlock_or_wait_invalidates_candidate_prefix(interruption):
    from types import SimpleNamespace
    from zscope.core.candidates.cpp_domains.shared_access import SharedAccessIndex

    semantics = default_local_pattern_semantics()
    semantics.merge_overlay(
        {
            "api_contracts": [
                {
                    "symbol": {"name": "alpha"},
                    "role": "lock",
                    "source": "user",
                    "protocol": {"lock_mode": "exclusive"},
                }
            ]
        }
    )
    lines = [
        SimpleNamespace(number=i + 1, index=i, text=text)
        for i, text in enumerate(["alpha(&m);", interruption, "shared++;"])
    ]
    index = SharedAccessIndex(
        lines, {}, set(semantics.lock_apis), set(semantics.unlock_apis), semantics.contracts
    )
    assert index.match(lines[-1])["global"] == "shared"


def test_mode_wrapper_from_actual_native_facts_and_reload(tmp_path):
    import json
    from test_single_slot_pool import native_index, native_context
    from zscope.semantics.build_scope import bind_build_scope
    from zscope.semantics.contract_compiler import deterministic_contract_snapshot

    source, database = tmp_path / "locks.c", tmp_path / "compile_commands.json"
    source.write_text(
        "#define _POSIX_C_SOURCE 200809L\n#include <pthread.h>\nint alpha(pthread_rwlock_t *p) { return pthread_rwlock_tryrdlock(p); }\nint omega(pthread_rwlock_t *p) { return pthread_rwlock_unlock(p); }\n"
    )
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", str(source)],
                }
            ]
        )
    )
    backend, index = native_index(tmp_path, source, database)
    try:
        registry = default_local_pattern_semantics().contracts
        contexts = [native_context(index, source, name) for name in ("alpha", "omega")]
        snapshots = [deterministic_contract_snapshot(ctx, registry) for ctx in contexts]
        _, semantics, _ = publish(tmp_path, snapshots)
        with bind_build_scope(contexts[0]):
            (contract,) = semantics.contracts.find_for_call("alpha", "lock", str(source))
            assert contract.lock_mode == "shared" and contract.effects_trusted
            assert (
                contract.symbol.build_context_id == contexts[0]["program_facts"]["build_context_id"]
            )
            assert contract.applicability(["&m"], "16") == "does_not_apply"
    finally:
        backend.close()
