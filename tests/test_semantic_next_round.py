from concurrent.futures import ThreadPoolExecutor
import threading

from zscope.common.cancellation import CancellationToken, bind_cancellation_token
from zscope.framework.base import AgentResponse
from zscope.agents.semantic_modeler.retry import run_semantic_model_with_retries
from zscope.snapshots.store import SnapshotStore
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.contract_compiler import derive_contracts
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.contract_review import proof_key, review_roots
from zscope.config.user_config_workbook import UserConfigWorkbook


def test_actual_retry_entry_single_owner_commits_before_waiters(tmp_path):
    root = CancellationToken()
    entered, finish = threading.Event(), threading.Event()
    calls = []
    stores = [SnapshotStore(tmp_path / "snapshots") for _ in range(6)]

    class Agent:
        def run(self, context):
            calls.append(context)
            entered.set()
            assert finish.wait(5)
            return AgentResponse(success=True, data={"interface_contracts": []}, metadata={})

    def request(store):
        with bind_cancellation_token(root.child()):
            result = run_semantic_model_with_retries(
                Agent,
                {
                    "func_name": "alpha",
                    "file_path": "a.c",
                    "signature": "void alpha(void)",
                    "code": "void alpha(void) { opaque(); }",
                },
                snapshot_store=store,
            )
            assert list((tmp_path / "snapshots/.modeling-tasks").glob("*.json"))
            return result

    with ThreadPoolExecutor(max_workers=6) as pool:
        jobs = [pool.submit(request, store) for store in stores]
        assert entered.wait(5)
        # Synchronize followers through coordinator metrics instead of sleeps.
        from zscope.orchestration.modeling_coordinator import scan_coordinator

        with bind_cancellation_token(root):
            coordinator = scan_coordinator(str(stores[0].snapshot_dir), stores[0])
        for _ in range(100000):
            if coordinator.metrics()["requests"] == 6:
                break
            threading.Event().wait(0.001)
        assert coordinator.metrics()["requests"] == 6
        finish.set()
        assert all(job.result().success for job in jobs)
    assert len(calls) == 1
    assert coordinator.metrics()["joined_requests"] == 5


def test_standard_roles_conditions_and_wrong_family():
    registry = default_local_pattern_semantics().contracts
    assert registry.find("pthread_mutex_init", "lock") == []
    assert registry.find("pthread_mutex_init", "lock_init")
    assert registry.find("calloc", "calloc")
    assert registry.allows("malloc", "free")
    assert not registry.allows("malloc", "fclose")
    robust = registry.match_call(
        "pthread_mutex_lock", "lock", ["&mu"], "r", facts={"r": 130, "EOWNERDEAD": 130}
    )
    assert robust[0].applicability == "applies"
    assert (
        registry.match_call(
            "pthread_mutex_lock", "lock", ["&mu"], "r", facts={"r": 22, "EOWNERDEAD": 130}
        )[0].applicability
        == "does_not_apply"
    )
    assert registry.match_call("free", "deallocator", ["NULL"])[0].applicability == "does_not_apply"


def test_branch_facts_reach_actual_call_events():
    registry = default_local_pattern_semantics().contracts
    context = {
        "func_name": "omega",
        "file_path": "a.c",
        "signature": "void omega(void *p)",
        "code": "void omega(void *p) { if (p) free(p); }",
    }
    event = registry.trace_calls(context)[0]
    assert event["applicability"] == "applies"
    assert event["callsite_facts"]["p"]
    context["code"] = "void omega(void *p) { free(p); }"
    assert registry.trace_calls(context)[0]["unknown_reason"] == "callsite_facts_missing"


def test_root_confirmation_recomputes_verified_wrappers_only(tmp_path):
    registry = default_local_pattern_semantics().contracts
    root = ApiContract.from_row(
        {
            "contract": {
                "symbol": {"name": "alpha", "file_path": "a.c"},
                "role": "allocator",
                "carrier": {"kind": "return"},
                "source": "inferred:semantic_modeling",
                "resource_family": "custom-pool",
                "verification": {"method": "schema_only"},
            }
        }
    )
    assert root is not None
    registry.add(root)
    context = {
        "func_name": "beta",
        "file_path": "b.c",
        "signature": "void *beta(void)",
        "code": "void *beta(void) { return alpha(); }",
    }
    derived = derive_contracts(context, registry)
    assert derived and not ApiContract.from_row({"contract": derived[0]}).effects_trusted
    review = review_roots([{"interface_contracts": [root.to_dict(), *derived]}], registry)
    assert [r["symbol_name"] for r in review["rows"]] == ["alpha"]
    assert review["rows"][0]["affected_interfaces"] == ["beta"]
    workbook = UserConfigWorkbook(tmp_path / "user_config.xlsx")
    workbook.write_rows({"contract_review": review["rows"]})
    assert workbook.import_confirmed_reviews()["imported"] == 0
    rows = workbook.read_rows()
    rows["contract_review"][0]["status"] = "confirmed"
    workbook.write_rows(rows)
    assert workbook.import_confirmed_reviews()["imported"] == 1
    imported = ApiContract.from_row(workbook.list_external_functions()[0])
    assert (
        imported
        and imported.effects_trusted
        and imported.source.startswith("user:contract_review:")
    )
    registry.add(imported)
    assert ApiContract.from_row(
        {"contract": derive_contracts(context, registry)[0]}
    ).effects_trusted
    rows = workbook.read_rows()
    rows["contract_review"][0]["status"] = "pending"
    workbook.write_rows(rows)
    workbook.import_confirmed_reviews()
    assert workbook.list_external_functions() == []
