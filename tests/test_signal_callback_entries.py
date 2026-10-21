import pytest

from zscope.orchestration.entry_discovery import EntryDiscovery
from test_entry_discovery import FakeCodeIndex


def discover(functions):
    return EntryDiscovery(FakeCodeIndex(functions)).discover()


def entries(functions):
    return {c.function_name: c for c in discover(functions).candidates}


HANDLER = "static void handler(int sig) { running = 0; }"


def test_signal_registers_callback_root_and_preserves_context_in_payload():
    result = discover(
        {
            "start": "void start(void) { signal(SIGINT, handler); signal(SIGTERM, &handler); }",
            "handler": HANDLER,
        }
    )
    assert result.exposure_kind == "callback_only"
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.function_name == "handler"
    assert candidate.exposure == "callback"
    assert set(candidate.reasons) == {"callback_context:signal", "callback_entry:signal"}
    assert "asynchronous signal handler" in candidate.custom_prompt
    assert "not proof" in candidate.custom_prompt
    assert result.to_function_entries()[0].exposure == "callback"
    assert result.to_entry_functions_payload()["functions"][0]["reasons"] == candidate.reasons


@pytest.mark.parametrize("argument", ["SIG_DFL", "SIG_IGN", "SIG_ERR", "NULL", "0", "(F)0"])
def test_non_callback_values_are_not_entries_even_with_matching_project_symbol(argument):
    result = entries(
        {
            "start": f"void start(void) {{ signal(SIGINT, {argument}); }}",
            "SIG_IGN": "void SIG_IGN(int sig) {}",
            "SIG_DFL": "void SIG_DFL(int sig) {}",
            "SIG_ERR": "void SIG_ERR(int sig) {}",
        }
    )
    assert not result


def test_signal_wrappers_follow_aliases_nested_forwarding_and_swapped_arguments():
    result = entries(
        {
            "inner": "void inner(int sig, F cb) { F saved = cb; signal(sig, saved); }",
            "outer": "void outer(F cb, int sig) { inner(sig, cb); }",
            "start": "void start(void) { outer(handler, SIGINT); }",
            "handler": HANDLER,
        }
    )
    assert result["handler"].reasons == ["callback_entry:outer", "callback_context:signal"]


@pytest.mark.parametrize(
    "body",
    [
        "struct sigaction sa = {0}; sa.sa_handler = handler; sa.sa_flags = 0; sigaction(SIGINT, &sa, 0);",
        "struct sigaction sa = {.sa_handler = handler, .sa_flags = 0}; sigaction(SIGINT, &sa, 0);",
        "struct sigaction sa = {0}; sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO | SA_RESTART; sigaction(SIGINT, &sa, 0);",
    ],
)
def test_sigaction_reads_new_action_handler(body):
    result = entries({"start": f"void start(void) {{ {body} }}", "handler": HANDLER})
    assert result["handler"].exposure == "callback"
    assert "callback_entry:sigaction" in result["handler"].reasons


def test_sigaction_wrapper_constructs_action_from_callback_parameter():
    result = entries(
        {
            "install": "int install(F cb) { struct sigaction sa = {0}; sa.sa_handler = cb; sa.sa_flags = 0; return sigaction(SIGINT, &sa, 0); }",
            "start": "void start(void) { install(handler); }",
            "handler": HANDLER,
        }
    )
    assert "callback_entry:install" in result["handler"].reasons


def test_sigaction_wrapper_forwards_action_pointer_members():
    result = entries(
        {
            "install": "int install(struct sigaction *action, int sig) { return sigaction(sig, action, 0); }",
            "start": "void start(void) { struct sigaction sa = {0}; sa.sa_handler = handler; sa.sa_flags = 0; install(&sa, SIGINT); }",
            "handler": HANDLER,
        }
    )
    assert "callback_entry:install" in result["handler"].reasons


def test_sigaction_union_uses_last_assignment_not_first_insertion_order():
    result = entries(
        {
            "start": "void start(void) { struct sigaction sa = {0}; sa.sa_handler = old; sa.sa_sigaction = alternate; sa.sa_handler = handler; sa.sa_flags = 0; sigaction(SIGINT, &sa, 0); }",
            "handler": HANDLER,
            "old": "void old(int sig) {}",
            "alternate": "void alternate(int sig) {}",
        }
    )
    assert set(result) == {"handler"}


def test_recursive_wrapper_does_not_expand_member_paths_forever():
    result = entries(
        {
            "install": "void install(struct sigaction *sa) { sigaction(SIGINT, sa, 0); install(sa->next); }",
            "start": "void start(void) { struct sigaction sa = {0}; sa.sa_handler = handler; install(&sa); }",
            "handler": HANDLER,
        }
    )
    assert "handler" in result


@pytest.mark.parametrize(
    "body",
    [
        "struct sigaction sa = {0}; sa.sa_handler = handler; sigaction(SIGINT, NULL, &sa);",
        "struct sigaction sa = {0}; sa.sa_handler = handler; sa.sa_handler = SIG_IGN; sigaction(SIGINT, &sa, 0);",
        "struct sigaction sa = {0}; sa.sa_sigaction = handler; sa.sa_flags = 0; sigaction(SIGINT, &sa, 0);",
        "struct sigaction sa = {0}; sa.sa_handler = handler; sa.sa_flags = SA_SIGINFO; sigaction(SIGINT, &sa, 0);",
        "struct sigaction sa = {0}; sa.sa_handler = handler; mutate(&sa); sigaction(SIGINT, &sa, 0);",
        '/* signal(SIGINT, handler); */ const char *s = "signal(SIGINT, handler)";',
    ],
)
def test_query_reset_wrong_member_and_non_code_do_not_register(body):
    assert not entries({"start": f"void start(void) {{ {body} }}", "handler": HANDLER})


def test_project_homonym_and_reassigned_parameter_do_not_inherit_registration():
    assert not entries(
        {
            "signal": "int signal(int sig, F cb) { return 0; }",
            "start": "void start(void) { signal(SIGINT, handler); }",
            "handler": HANDLER,
        }
    )
    assert not entries(
        {
            "install": "void install(F cb) { cb = SIG_IGN; signal(SIGINT, cb); }",
            "start": "void start(void) { install(handler); }",
            "handler": HANDLER,
        }
    )


def test_registration_after_loop_and_exit_callback():
    result = entries(
        {
            "start": "void start(void) { for (int i = 0; i < 2; i++) work(); signal(SIGINT, handler); atexit(cleanup); }",
            "handler": HANDLER,
            "cleanup": "void cleanup(void) {}",
        }
    )
    assert result["handler"].exposure == result["cleanup"].exposure == "callback"
    assert result["cleanup"].reasons == ["callback_entry:atexit", "callback_context:exit"]
    assert "asynchronous signal" not in result["cleanup"].custom_prompt


def test_callback_keeps_a_slot_under_entry_budget():
    from zscope.orchestration.entry_discovery import EntryCandidate

    candidates = [EntryCandidate(f"Api{i}", "api", confidence=0.99) for i in range(10)]
    candidates.append(EntryCandidate("handler", "callback", confidence=0.88))
    assert "handler" in {c.function_name for c in EntryDiscovery._select_stratified(candidates, 2)}


def test_real_source_index_selects_callback_and_uses_its_actual_location(tmp_path):
    from zscope.retrieval.code_index import CodeIndex

    source = tmp_path / "main.c"
    source.write_text(
        "#include <signal.h>\n"
        "static volatile sig_atomic_t running;\n"
        "static void handler(int sig) { running = 0; }\n"
        "void install(void) { signal(SIGINT, handler); }\n",
        encoding="utf-8",
    )
    index = CodeIndex(tmp_path, source_root=tmp_path)
    try:
        result = EntryDiscovery(index, project_root=tmp_path, source_root=tmp_path).discover()
        relations = index.callback_registrations()
        registration = next(e for e in relations if e["callee_name"] == "handler")
        assert registration["call_type"] == "callback_registration"
        assert registration["execution"] == "asynchronous"
        assert registration["registration_success"] == "unknown"
        assert registration["call_line"] == 4
        assert any(e.get("call_type") == "callback_registration" for e in index.get_callees("install"))
        assert any(e.get("call_type") == "callback_registration" for e in index.get_callers("handler"))
        source.write_text(source.read_text().replace("signal(SIGINT, handler)", "signal(SIGINT, SIG_IGN)"), encoding="utf-8")
        assert index.callback_registrations() == []
    finally:
        index.close()
    handler = next(c for c in result.candidates if c.function_name == "handler")
    assert handler.file_path == "main.c"
    assert handler.line == 3
    assert handler.signature == "static void handler(int sig)"
    assert handler.exposure == "callback"


def test_callback_root_reaches_validator_as_external_context_without_direct_callers():
    from types import SimpleNamespace
    from zscope.core.validation.evidence import build_validation_evidence_pack

    candidate = entries(
        {
            "start": "void start(void) { signal(SIGINT, handler); }",
            "handler": HANDLER,
        }
    )["handler"]
    index = SimpleNamespace(
        get_callers=lambda *a, **kw: [],
        get_callees=lambda *a, **kw: [],
        get_file_content=lambda *a, **kw: HANDLER,
        get_function_impl=lambda *a, **kw: {"code": HANDLER},
    )
    state = {
        "entry_func": "handler",
        "agent_context": {
            "func_name": "handler",
            "entry_custom_prompt": candidate.custom_prompt,
        },
    }
    pack = build_validation_evidence_pack(
        {"id": "test", "function": "handler", "category": "race_condition"},
        state,
        HANDLER,
        code_index=index,
        snapshot_store=SimpleNamespace(get=lambda *a, **kw: None),
        score_components_fn=lambda *args: {},
    )
    assert pack["entry_context"]["entry_exposure"] == "callback"
    assert pack["entry_context"]["entry_is_external_root"] is True
    assert pack["entry_context"]["reachable_from_entry"] is True
    assert "asynchronous signal handler" in pack["entry_context"]["entry_custom_prompt"]
