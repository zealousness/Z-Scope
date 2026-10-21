import gc
import json
import weakref

from zscope.benchmarking import runner
from zscope.reporting.shared_objects import ObjectEncoder, decode_storage


def test_archive_summary_releases_shared_report_graph(monkeypatch, tmp_path):
    original = {
        "metadata": {"benchmark_ablation": {"enabled": ["one"]}},
        "run_manifest": {
            "config_hash": "cfg",
            "runtime_spec": {"version": 3},
            "rule_catalog": {"rules": ["a", "b"]},
        },
        "summary": {"batch_wall_seconds": 123},
        "issues": [{"evidence": {"source": "complete source", "facts": [1, 2, 3]}}],
    }
    refs = []

    def load(path):
        report = decode_storage(ObjectEncoder().envelope(original))
        refs.append(weakref.ref(report._decoder))
        return report

    persisted = []

    def dump(path, payload):
        persisted.append((path.name, json.loads(json.dumps(payload))))

    def replay(path, report):
        assert report["issues"] == original["issues"]
        # Return nested shared values to verify the detached summary also handles
        # future structured bundle metadata without retaining its decoder.
        return {
            "schema_version": "v1",
            "group_count": 1,
            "bundle_sha256": "abc",
            "canonical_groups": report["issues"],
        }

    monkeypatch.setattr(runner, "_load_json_object", load)
    monkeypatch.setattr(runner, "_json_dump", dump)
    monkeypatch.setattr(runner, "_archive_usage_events", lambda *a, **k: None)
    monkeypatch.setattr(runner, "write_validator_replay_bundle", replay)
    summary = runner._archive_report_for_scoring(
        tmp_path / "report.json", tmp_path / "source", tmp_path, {"source_line_count": 42}
    )
    gc.collect()
    assert refs and all(ref() is None for ref in refs)
    assert summary == {
        "replay_bundle": {"schema_version": "v1", "group_count": 1, "bundle_sha256": "abc"},
        "report_has_batch_wall": True,
        "report_ablation": {"enabled": ["one"]},
        "report_provenance": {
            "config_hash": "cfg",
            "runtime_spec": {"version": 3},
            "rule_catalog": {"rules": ["a", "b"]},
        },
    }
    report = next(value for name, value in persisted if name == "report.json")
    assert report["issues"] == original["issues"]
    assert report["metadata"]["source_line_count"] == 42
    assert report["run_manifest"]["source_line_count"] == 42
