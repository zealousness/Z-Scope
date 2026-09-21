from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

from zscope.reporting.immutable_evidence import ImmutableEvidencePool
from zscope.reporting.shared_objects import ObjectEncoder, ObjectDecoder


def test_terminal_evidence_clones_share_content_but_not_changes():
    pool = ImmutableEvidencePool()
    original = {"evidence": {"nodes": [{"value": i} for i in range(500)]}, "status": "confirmed"}
    first = pool.clone(original)
    count = len(pool._encoder.objects)
    second = pool.clone(original)
    assert len(pool._encoder.objects) == count
    assert first._decoder is second._decoder
    first["evidence"]["nodes"][3]["value"] = "amended"
    assert second["evidence"]["nodes"][3]["value"] == 3
    assert original["evidence"]["nodes"][3]["value"] == 3
    third = deepcopy(first)
    third["evidence"]["nodes"].append({"value": "new"})
    assert len(first["evidence"]["nodes"]) == 500
    original["evidence"]["nodes"][5]["value"] = "input changed"
    assert second["evidence"]["nodes"][5]["value"] == 5
    decoded = ObjectDecoder(ObjectEncoder().envelope(third)).root
    assert decoded == third
    assert pool._encoder._identities == {}


def test_internal_non_json_values_keep_legacy_types_and_isolation():
    pool = ImmutableEvidencePool()
    for original in ({"value": (1, 2)}, {3: ["integer key"]}, {"value": {1, 2}}):
        cloned = pool.clone(original)
        assert cloned == original
        assert cloned is not original
        assert type(next(iter(cloned.values()))) is type(next(iter(original.values())))
    assert pool.fallback_clones == 3


def test_concurrent_terminal_freezes_keep_every_result_independent():
    pool = ImmutableEvidencePool()
    with ThreadPoolExecutor(max_workers=4) as executor:
        values = list(
            executor.map(
                lambda i: pool.clone({"candidate": i, "facts": {"same": list(range(40))}}),
                range(12),
            )
        )
    for index, value in enumerate(values):
        assert value["candidate"] == index
        value["facts"]["same"][0] = index + 10
    assert [v["facts"]["same"][0] for v in values] == list(range(10, 22))
