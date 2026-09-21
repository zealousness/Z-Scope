from dataclasses import replace
import pytest

from zscope.semantics.contracts import ApiContract, ContractRegistry, ObjectBinding
from zscope.semantics.contract_review import proof_key, review_roots


def root():
    value = ApiContract.from_row(
        {
            "contract": {
                "symbol": {"name": "root", "file_path": "root.c"},
                "role": "allocator",
                "carrier": {"kind": "return"},
                "resource_family": "pool-one",
                "resource_domain": {"kind": "argument", "argument_index": 0},
                "source": "inferred:semantic_modeling",
                "verification": {"method": "schema_only"},
            }
        }
    )
    assert value is not None
    return value


@pytest.mark.parametrize(
    "changes",
    [
        {"resource_family": "pool-two"},
        {"resource_domain": ObjectBinding(kind="argument", argument_index=1)},
        {"preconditions": {"op": "false"}},
        {"effect_cases": [{"when": {"op": "true"}, "effect": "no_effect"}]},
        {"protocol": {"kind": "independent"}},
    ],
)
def test_confirmation_of_one_specification_does_not_prove_a_different_one(changes):
    original = root()
    confirmed = replace(original, source="user")
    other = replace(original, **changes)
    assert proof_key(confirmed) == proof_key(original)
    registry = ContractRegistry()
    registry.add(confirmed)
    review = review_roots([{"interface_contracts": [other.to_dict()]}], registry)
    assert len(review["rows"]) == 1
    assert review["rows"][0]["review_id"] == proof_key(other)
    assert proof_key(other) != proof_key(original)
