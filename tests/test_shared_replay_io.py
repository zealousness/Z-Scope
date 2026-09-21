import json
import pytest

from test_validator_replay import _report
from zscope.benchmarking.replay_bundle import (
    ReplayBundleError, load_validator_replay_bundle, write_validator_replay_bundle,
)
from zscope.reporting.json_io import read_report, write_json_atomic
from zscope.reporting.shared_objects import STORAGE_SCHEMA


def test_replay_writer_and_strict_reader_preserve_legacy_bindings(tmp_path):
    path = tmp_path / 'shared.json'
    expected = write_validator_replay_bundle(path, _report())
    envelope = json.loads(path.read_text())
    assert envelope['storage_schema'] == STORAGE_SCHEMA
    actual = load_validator_replay_bundle(path)
    legacy = tmp_path / 'legacy.json'
    write_json_atomic(legacy, expected)
    assert actual == load_validator_replay_bundle(legacy) == expected
    assert actual['bundle_sha256'] == expected['bundle_sha256']
    assert [r['group_sha256'] for r in actual['canonical_groups']] == [r['group_sha256'] for r in expected['canonical_groups']]


@pytest.mark.parametrize('contents', ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'])
def test_strict_shared_io_keeps_duplicate_and_nonfinite_rejection(tmp_path, contents):
    path = tmp_path / 'bad.json'
    path.write_text(contents)
    with pytest.raises(ValueError):
        read_report(path, strict=True)
    with pytest.raises(ReplayBundleError):
        load_validator_replay_bundle(path)


def test_replay_reader_checks_shared_references_and_digests(tmp_path):
    path = tmp_path / 'shared.json'
    write_validator_replay_bundle(path, _report())
    original = json.loads(path.read_text())
    uid = original['root'][1]
    missing = dict(original, objects={k: v for k, v in original['objects'].items() if k != uid})
    path.write_text(json.dumps(missing))
    with pytest.raises(ReplayBundleError, match='reference'):
        load_validator_replay_bundle(path)
    original['objects'][uid] = ['value', 'changed']
    path.write_text(json.dumps(original))
    with pytest.raises(ReplayBundleError, match='integrity'):
        load_validator_replay_bundle(path)
