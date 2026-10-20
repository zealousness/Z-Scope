"""Real batch/AST facts and scoped guard proof consumption in the Validator."""

from copy import deepcopy
import json
import shutil

import pytest

from test_single_slot_pool import native_index
from test_review_fact_checks import issue
from zscope.core.validation.review_checks import ReviewClaimChecker, checked_receipt
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.retrieval.validation_facts import CompleteFactStore

PRELUDE = (
    'extern "C" void *malloc(unsigned long) noexcept;\nextern "C" void free(void*) noexcept;\n'
)
GUARD = "struct Guard { void *p; explicit Guard(void *x) noexcept : p(x) {} ~Guard() noexcept { if(p) free(p); } };\n"


@pytest.fixture
def cpp_project(tmp_path):
    backends = []

    def build(body, guard=GUARD, extra="", flags=()):
        path = tmp_path / "subject.cpp"
        path.write_text(
            PRELUDE + extra + guard + "void f(bool flag) {\n" + body + "\n}\n", encoding="utf-8"
        )
        compiler = shutil.which("clang++")
        assert compiler
        cdb = tmp_path / "compile_commands.json"
        cdb.write_text(
            json.dumps(
                [
                    {
                        "directory": str(tmp_path),
                        "file": str(path),
                        "arguments": [compiler, "-std=c++17", *flags, "-c", str(path)],
                    }
                ]
            ),
            encoding="utf-8",
        )
        store = CompleteFactStore(tmp_path, cdb, tmp_path / ".zscope_review_facts", clang=compiler)
        descriptor = store.collect(str(path))
        assert descriptor.get("complete"), descriptor
        backend, index = native_index(tmp_path, path, cdb)
        backends.append(backend)
        facts = index.get_function_program_facts("f", str(path))
        assert facts["complete"], facts
        candidate = issue(
            path,
            source="p allocated here",
            build_context_id=facts["build_context_id"],
            rule_revision=10,
        )
        checker = ReviewClaimChecker(store, program_facts_provider=index.get_function_program_facts)
        checker.prepare(candidate)
        return checker, candidate, index, path

    yield build
    for backend in backends:
        backend.close()


def verdict(project):
    checker, candidate, _, _ = project
    result = checker.check(candidate)
    return result, candidate.get("lifecycle_analysis", {})


@pytest.mark.parametrize(
    "body",
    [
        "void *p=malloc(8); Guard g(p);",
        "void *p=malloc(8); { Guard g(p); }",
        "void *p=malloc(8); Guard g(p); if(flag) return;",
        "void *p=malloc(8); if (!p) return; Guard g(p);",
        "try { void *p=malloc(8); Guard g(p); if(flag) throw 1; } catch(...) {}",
        "try { void *p=malloc(8); Guard g(p); throw 1; } catch(...) {}",
        "void *p=malloc(8); Guard g(p); p=nullptr;",
    ],
)
def test_current_guard_discharges_exact_object_on_supported_exits(cpp_project, body):
    project = cpp_project(body)
    result, analysis = verdict(project)
    assert result["status"] == "supported", (result, analysis)
    assert analysis["obligations"][0]["status"] == "discharged"
    events = [e for e in analysis["events"] if e["kind"] == "scoped_guard_cleanup"]
    assert events and all(
        e["manager_usr"] and e["destructor_usr"] and e["build_context_id"] for e in events
    )
    if "throw" in body:
        assert any(e["exit_kind"] == "caught_throw_unwind" for e in events)
    assert checked_receipt(project[1])
    assert deterministic_decision_proof(project[1], outcome="reject")


@pytest.mark.parametrize(
    "body,guard,extra",
    [
        ("void *p=malloc(8); Guard g(nullptr);", GUARD, ""),
        ("void *p=malloc(8); Guard g(p);", GUARD.replace("if(p) free(p);", ""), ""),
        ("void *p=malloc(8); Guard g(p);", GUARD.replace("p(x)", "p(nullptr)"), ""),
        ("void *p=malloc(8); Guard g(p);", GUARD.replace("if(p)", "if(!p)"), ""),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD.replace("free(p)", "custom(p)"),
            "void custom(void*) noexcept;\n",
        ),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD.replace("explicit Guard(void *x) noexcept", "explicit Guard(void *x)"),
            "",
        ),
        ("void *p=malloc(8); Guard g(p); g.p=nullptr;", GUARD, ""),
        ("void *p=malloc(8); Guard g(p); Guard copy(g);", GUARD, ""),
        ("void *p=malloc(8); Guard g(p); Guard moved(static_cast<Guard&&>(g));", GUARD, ""),
        ("void *p=malloc(8); Guard g(p); g.~Guard();", GUARD, ""),
        ("void *p=malloc(8); Guard g(p); free(p);", GUARD, ""),
        ("void *p=malloc(8); Guard g(p); if(flag) throw 1;", GUARD, ""),
        ("void *p=malloc(8); Guard g(p); unknown();", GUARD, "void unknown();\n"),
        ("void *p=malloc(8); if(flag) { Guard g(p); }", GUARD, ""),
        ("void *p=malloc(8); static Guard g(p);", GUARD, ""),
        ("void *p=malloc(8); Guard g(p); escape(&g);", GUARD, ""),
        (
            "void *p=malloc(8); Guard g(p); g.reset();",
            GUARD.replace("~Guard()", "void reset() noexcept {} ~Guard()"),
            "",
        ),
        (
            "void *p=malloc(8); Guard g(p); g.release();",
            GUARD.replace("~Guard()", "void release() noexcept {} ~Guard()"),
            "",
        ),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD.replace("free(p)", "other::free(p)"),
            "namespace other { void free(void*) noexcept; }\n",
        ),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD.replace("free(p)", "other::custom(p)"),
            "void custom(void *p) noexcept {free(p);}\nnamespace other {void custom(void*) noexcept;}\n",
        ),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD + 'extern "C" void free(void*) noexcept {}\n',
            "",
        ),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD.replace("p(x)", "p(x)").replace("{} ~Guard", "{ if(x) throw 1; } ~Guard"),
            "",
        ),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD.replace("~Guard() noexcept", "~Guard() noexcept(false)"),
            "",
        ),
        (
            "void *p=malloc(8); Guard g(p);",
            GUARD.replace("if(p) free(p);", "if(p) {free(p); free(p);}"),
            "",
        ),
    ],
)
def test_unknown_or_partial_raii_cannot_refute(cpp_project, body, guard, extra):
    if "escape" in body:
        guard += "void escape(Guard*) noexcept;\n"
    project = cpp_project(body, guard, extra)
    result, analysis = verdict(project)
    assert result["status"] == "unknown", (result, analysis)
    assert not checked_receipt(project[1])


def test_current_custom_deleter_is_rechecked_and_bound(cpp_project):
    project = cpp_project(
        "void *p=malloc(8); Guard g(p);",
        GUARD.replace("free(p)", "custom(p)"),
        "void custom(void *p) noexcept { free(p); }\n",
    )
    assert verdict(project)[0]["status"] == "supported"
    project[3].write_text(project[3].read_text().replace("{ free(p); }", "{}"))
    assert not checked_receipt(project[1])
    assert project[0].check(project[1])["status"] == "unknown"


@pytest.mark.parametrize("build", ["", "other-build"])
def test_unknown_or_other_build_cannot_borrow_guard(cpp_project, build):
    project = cpp_project("void *p=malloc(8); Guard g(p);")
    assert verdict(project)[0]["status"] == "supported"
    project[1]["build_context_id"] = build
    assert not checked_receipt(project[1])
    assert verdict(project)[0]["status"] == "unknown"


def test_native_lifetime_identity_is_required_and_event_label_not_authority(cpp_project):
    project = cpp_project("void *p=malloc(8); Guard g(p);")
    checker, candidate, index, path = project
    assert verdict(project)[0]["status"] == "supported"
    facts = deepcopy(index.get_function_program_facts("f", str(path)))
    assert any(
        e.get("destructor", {}).get("usr")
        for e in facts["events"]
        if e["event_kind"] == "implicit_release"
    )
    facts["functions"][0].pop("cxx_lifetime_facts_version")
    checker.program_facts_provider = lambda *a, **k: facts
    result, analysis = verdict(project)
    assert result["status"] == "unknown"
    assert "raii_native_lifetime_facts_missing" in analysis["gaps"]
    assert not checked_receipt(candidate)


def test_two_resources_and_empty_guard_do_not_merge(cpp_project):
    project = cpp_project("void *p=malloc(8); Guard g(p); void *q=malloc(8); Guard empty(nullptr);")
    assert verdict(project)[0]["status"] == "supported"
    project[1]["source"] = "q allocated here"
    assert verdict(project)[0]["status"] == "unknown"


def test_real_standard_header_and_distinct_acquisitions(cpp_project):
    project = cpp_project(
        "void *p=malloc(8); Guard first(p); p=malloc(16); Guard second(p);",
        extra="#include <cstdlib>\n",
    )
    result, analysis = verdict(project)
    assert result["status"] == "supported", (result, analysis)
    obligations = analysis["obligations"]
    assert len(obligations) == 2 and len({o["acquisition_id"] for o in obligations}) == 2
    assert all(o["status"] == "discharged" for o in obligations)


def test_deleted_technical_evidence_or_model_score_cannot_authorize_raii(cpp_project):
    project = cpp_project("void *p=malloc(8); Guard g(nullptr);")
    project[1].update(confidence=1.0, proof_complete=True, unresolved_gaps=[])
    assert verdict(project)[0]["status"] == "unknown"
    assert not deterministic_decision_proof(project[1], outcome="reject")


def test_real_candidate_consumes_raii_without_enabling_experimental_default(cpp_project):
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.rules.catalog import RuleCatalog, EffectiveRuleSet

    checker, _, index, path = cpp_project("void *p=malloc(8);\nGuard g(p);")
    code = index.get_function_impl("f", file_path=str(path), include_context=False)["code"]
    descriptor = RuleCatalog.builtin().require("clang_cfg_acquire_without_release_on_exit")
    assert not descriptor.default_enabled and descriptor.status == "experimental"
    policy = EffectiveRuleSet.build(
        RuleCatalog.builtin(), language="c_cpp", backend="clang", enabled_ids=[descriptor.id]
    ).policy
    generated = ClangAstCfgCandidateGenerator(
        rule_policy=policy, program_facts_provider=index.get_function_program_facts
    ).generate_issues("f", code, str(path))
    candidates = [i for i in generated if i["rule_id"] == descriptor.id]
    assert candidates
    for candidate in candidates:
        candidate = policy.enrich_issue(candidate)
        assert candidate["build_context_id"]
        assert candidate["rule_revision"] == 11
        checker.prepare(candidate)
        result = checker.check(candidate)
        assert result["status"] == "supported", (result, candidate.get("lifecycle_analysis"))
        assert checked_receipt(candidate)


def test_hot_raii_cannot_reuse_invalidated_native_inventory(cpp_project):
    project = cpp_project("void *p=malloc(8); Guard g(p);")
    assert verdict(project)[0]["status"] == "supported"
    project[3].with_name("new_target.cpp").write_text("void added() {}\n")
    assert not checked_receipt(project[1])
    result, analysis = verdict(project)
    assert result["status"] == "unknown"
    assert "raii_build_or_native_receipt_unbound" in analysis["gaps"]
    cdb = project[0].store.compile_commands
    commands = json.loads(cdb.read_text())
    added = project[3].with_name("new_target.cpp")
    commands.append(
        {
            "directory": str(added.parent),
            "file": str(added),
            "arguments": [commands[0]["arguments"][0], "-std=c++17", "-c", str(added)],
        }
    )
    cdb.write_text(json.dumps(commands))
    assert project[2]._backend._run_full_extraction()
    project[0].prepare(project[1])
    assert verdict(project)[0]["status"] == "supported"
