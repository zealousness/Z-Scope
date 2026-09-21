"""Validation context selection must depend on indexed origin, not spelling."""
from types import SimpleNamespace

import pytest

from zscope.core.validation.runner import ValidationRunner


def _select(name, *, origin=None, classifier=True, body=False, failure=False):
    requests = []

    def implementation(symbol, **kwargs):
        if symbol == "caller" or body:
            return {"code": f"void {symbol}(void) {{}}"}
        return None

    def classify(symbol, caller=""):
        requests.append((symbol, caller))
        if failure:
            raise RuntimeError("index unavailable")
        return origin

    index = SimpleNamespace(get_function_impl=implementation)
    if classifier:
        index.call_model_status = classify
    runner = object.__new__(ValidationRunner)
    runner.code_index = index
    issue = {"function": name, "entry_function": "caller"}
    state = {"entry_func": "caller", "agent_context": {"func_name": "caller"}}
    selected = runner._issue_function(issue, state)
    return selected, issue, requests


@pytest.mark.parametrize("name", ["opaque_api", "VOS_Alloc", "OSAL_Alloc", "pthread_create"])
@pytest.mark.parametrize("origin", ["standard_model", "external_model_missing"])
def test_declared_external_interfaces_select_context_independently_of_name(name, origin):
    selected, issue, requests = _select(name, origin=origin)
    assert selected == "caller"
    assert issue["sink_function"] == name
    assert issue["validation_function_normalized_from"] == name
    assert issue["validation_function_normalization_origin"] == origin
    assert requests == [(name, "caller")]


@pytest.mark.parametrize("name", ["opaque_api", "VOS_Alloc", "OSAL_Alloc", "malloc"])
@pytest.mark.parametrize("origin", ["project", "source_unavailable", ""])
def test_project_or_unresolved_origin_keeps_original_function(name, origin):
    selected, issue, _ = _select(name, origin=origin)
    assert selected == name
    assert "validation_function_normalized_from" not in issue


@pytest.mark.parametrize("name", ["VOS_Alloc", "OSAL_Alloc", "pthread_create"])
def test_missing_classifier_does_not_guess_external_origin(name):
    selected, issue, _ = _select(name, classifier=False)
    assert selected == name
    assert "sink_function" not in issue


def test_origin_lookup_failure_keeps_original_function():
    selected, issue, _ = _select("malloc", failure=True)
    assert selected == "malloc"
    assert "validation_function_normalized_from" not in issue


@pytest.mark.parametrize("origin", [None, {}, ["standard_model"]])
def test_malformed_origin_is_not_external_evidence(origin):
    selected, issue, _ = _select("malloc", origin=origin)
    assert selected == "malloc"
    assert "validation_function_normalized_from" not in issue


def test_local_definition_with_standard_name_precedes_external_classification():
    selected, issue, requests = _select("malloc", origin="standard_model", body=True)
    assert selected == "malloc"
    assert "validation_function_normalized_from" not in issue
    assert requests == []
