import pytest

from zscope.orchestration.entry_discovery import EntryDiscovery

from test_entry_discovery import FakeCodeIndex


def names(functions):
    result = EntryDiscovery(FakeCodeIndex(functions)).discover()
    return {c.function_name: c for c in result.candidates}


@pytest.mark.parametrize("name", ["opaque", "VOS_TaskCreate", "OSAL_TaskCreate"])
def test_project_spelling_without_implementation_does_not_imply_thread_creation(name):
    result = names(
        {
            "start": f"int start(void) {{ return {name}(0, worker, worker, 0); }}",
            "worker": "void *worker(void *arg) { return arg; }",
        }
    )
    assert "worker" not in result


@pytest.mark.parametrize("wrapper", ["alpha", "renamed", "VOS_TaskCreate"])
def test_source_parameter_forwarding_discovers_renamed_wrappers(wrapper):
    result = names(
        {
            wrapper: f"int {wrapper}(F callback, void *ctx) {{ pthread_t t; return pthread_create(&t, 0, callback, ctx); }}",
            "start": f"int start(void) {{ return {wrapper}(worker, 0); }}",
            "worker": "void *worker(void *arg) { return arg; }",
        }
    )
    assert result["worker"].reasons == [f"thread_entry:{wrapper}"]


def test_nested_wrappers_follow_swapped_arguments():
    result = names(
        {
            "alpha": "int alpha(F callback, void *ctx) { pthread_t t; return pthread_create(&t, 0, callback, ctx); }",
            "beta": "int beta(void *ctx, int unused, F callback) { return alpha(callback, ctx); }",
            "start": "int start(void) { return beta(0, 0, worker); }",
            "worker": "void *worker(void *arg) { return arg; }",
        }
    )
    assert result["worker"].reasons == ["thread_entry:beta"]


def test_reassigned_callback_and_project_homonym_do_not_inherit_standard_semantics():
    result = names(
        {
            "alpha": "int alpha(F callback) { callback = 0; pthread_t t; return pthread_create(&t, 0, callback, 0); }",
            "start": "int start(void) { return alpha(worker); }",
            "worker": "void *worker(void *arg) { return arg; }",
        }
    )
    assert "worker" not in result
    result = names(
        {
            "pthread_create": "int pthread_create(void *a, void *b, F callback, void *d) { return 0; }",
            "start": "int start(void) { return pthread_create(0, 0, worker, 0); }",
            "worker": "void *worker(void *arg) { return arg; }",
        }
    )
    assert "worker" not in result
