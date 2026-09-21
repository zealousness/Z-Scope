"""Checkpoint references reuse immutable evidence without losing dependencies."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3

from zscope.reporting.evidence_objects import EvidenceObjectStore
from zscope.reporting.shared_objects import ObjectEncoder, ObjectDecoder


def evidence():
    return {'facts': [{'ordinal': i, 'source': 'int value = 7;' * 30, 'children': [i, {'value': i}]} for i in range(1000)]}


def test_unchanged_evidence_does_not_reencode_stored_graph(tmp_path, monkeypatch):
    original = evidence()
    store = EvidenceObjectStore(tmp_path)
    first = store.put(original)
    shared = store.get(first)
    visits = []
    method = ObjectEncoder._import_refs

    def observe(self, node, decoder):
        visits.append(node)
        return method(self, node, decoder)

    monkeypatch.setattr(ObjectEncoder, '_import_refs', observe)
    second = store.put({'stage': 'later', 'evidence': shared})
    assert store.get(second) == {'stage': 'later', 'evidence': original}
    assert len(visits) <= 2


def test_changed_view_and_other_database_keep_complete_evidence(tmp_path):
    original = evidence()
    first_store = EvidenceObjectStore(tmp_path / 'first')
    first = first_store.put(original)
    view = first_store.get(first)
    view['facts'][5]['children'][1]['value'] = 'changed'
    amended = first_store.put(view)
    assert first_store.get(amended)['facts'][5]['children'][1]['value'] == 'changed'
    assert first_store.get(first) == original
    other = EvidenceObjectStore(tmp_path / 'other')
    copied = other.put(first_store.get(amended))
    assert other.get(copied) == first_store.get(amended)
    assert copied == amended


def test_replaced_database_cannot_reuse_old_reference_cache(tmp_path):
    store = EvidenceObjectStore(tmp_path)
    original = evidence()
    first = store.put(original)
    shared = store.get(first)
    # Replace atomically with a valid empty database; the old inode remains
    # allocated so the replacement cannot accidentally reuse its identity.
    old = tmp_path / 'old.sqlite3'
    store.path.rename(old)
    replacement = sqlite3.connect(store.path)
    replacement.execute('CREATE TABLE objects (digest TEXT PRIMARY KEY,node TEXT NOT NULL)')
    replacement.close()
    second = store.put(shared)
    assert store.get(second) == original


def test_parallel_append_and_self_contained_report_remain_complete(tmp_path):
    store = EvidenceObjectStore(tmp_path)
    original = evidence()
    initial = store.put(original)
    with ThreadPoolExecutor(max_workers=4) as pool:
        refs = list(pool.map(lambda i: store.put({'stage': i, 'facts': store.get(initial)}), range(8)))
    for i, reference in enumerate(refs):
        assert store.get(reference) == {'stage': i, 'facts': original}
    envelope = ObjectEncoder().envelope(store.get(refs[0]))
    assert ObjectDecoder(json.loads(json.dumps(envelope))).root == {'stage': 0, 'facts': original}
