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


def test_candidate_pipeline_reuses_deterministic_signal_batch_per_entry() -> None:
    calls = {"local": 0, "graph": 0, "backend": 0}

    def detector(name, result):
        def run(_state):
            calls[name] += 1
            return [result]

        return run

    pipeline = CandidatePipeline(
        local_detector=detector("local", {"id": "l"}),
        graph_detector=detector("graph", {"id": "g"}),
        backend_detector=detector("backend", {"id": "b"}),
        unified_merger=lambda candidates: list(candidates),
        budget_refresher=lambda *_args, **_kwargs: None,
        candidate_persister=lambda _candidates: None,
    )
    state = {}

    first = pipeline.collect_signal_candidates(state)
    second = pipeline.collect_signal_candidates(state)

    assert calls == {"local": 1, "graph": 1, "backend": 1}
    assert first.merged_candidates == second.merged_candidates
