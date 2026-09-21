"""Explicit test-project contracts; these names are never product defaults."""

from zscope.semantics.contracts import ApiContract
from zscope.semantics.models import LocalPatternSemantics


def configured_test_semantics() -> LocalPatternSemantics:
    semantics = LocalPatternSemantics()
    definitions = {
        "allocator": [
            "_safe_malloc",
            "_str_dup",
            "_safe_strdup",
            "_service_alloc_node",
            "_real_model_alloc_node",
            "make_child",
            "duplicate",
        ],
        "calloc": ["_safe_calloc", "SAFE_CALLOC"],
        "reallocator": ["_safe_realloc"],
        "deallocator": ["SAFE_FREE", "session_release"],
        "lock": ["LOCK", "LOCK_READ", "LOCK_WRITE", "_lock_wrapper"],
        "unlock": ["UNLOCK", "_unlock_wrapper"],
        "recv_source": ["_net_recv_data"],
        "send_sink": ["_net_send_data"],
        "callback_register": ["register_callback"],
        "ownership_transfer": ["_real_model_fake_avl_insert", "_node_insert_locked"],
        "format_sink": ["LOG_ERROR"],
    }
    for role, names in definitions.items():
        for name in names:
            pair = (
                ["UNLOCK"]
                if role == "lock"
                else (["SAFE_FREE"] if role in {"allocator", "calloc", "reallocator"} else [])
            )
            contract = ApiContract.from_row(
                {"symbol_name": name, "kind": role, "source": "test:user_config", "pair": pair}
            )
            if role in {"allocator", "calloc", "reallocator"}:
                from zscope.semantics.standard_api import standard_contracts
                from dataclasses import replace
                contract = replace(contract, protocol=next(c["protocol"] for c in standard_contracts()
                                         if c["symbol"]["name"] == {"allocator": "malloc", "calloc": "calloc", "reallocator": "realloc"}[role]))
            semantics.contracts.add(contract)
            semantics.add_api(role, name, "test:user_config")
    return semantics
