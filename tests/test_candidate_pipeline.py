from zscope.core.candidates.pipeline import CandidatePipeline


def test_candidate_pipeline_collects_merges_summarizes_and_persists() -> None:
    refreshed = []
    persisted = []

    pipeline = CandidatePipeline(
        local_detector=lambda state: [
            {"id": "r", "candidate_source": "regex_local_rule"},
            {"id": "c", "candidate_source": "clang_ast_cfg"},
        ],
        graph_detector=lambda state: [{"id": "g", "candidate_source": "graph"}],
        backend_detector=lambda state: [
            {"id": "s", "candidate_source": "svf_value_flow"},
            {"id": "b", "candidate_source": "clang_knowledgedb_call_edges"},
        ],
        unified_merger=lambda candidates: candidates[:3],
        budget_refresher=lambda *args, **kwargs: refreshed.append((args, kwargs)),
        candidate_persister=lambda candidates: persisted.extend(candidates),
    )

    state = {}
    batch = pipeline.collect_signal_candidates(state)
    summary = pipeline.accumulate_summary(state, batch)
    pipeline.persist(batch)

    assert [item["id"] for item in batch.merged_candidates] == ["r", "c", "g"]
    assert summary == {
        "regex": 1,
        "clang_ast_cfg": 1,
        "svf_value_flow": 1,
        "graph": 1,
        "backend": 2,
        "total": 3,
    }
    assert len(refreshed) == 1
    assert refreshed[0][0][1] == "candidate_signals"
    assert [item["id"] for item in persisted] == ["r", "c", "g"]
