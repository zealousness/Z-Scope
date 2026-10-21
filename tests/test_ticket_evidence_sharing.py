import gc
import weakref
from zscope.orchestration.candidates import CandidateLedger
from zscope.reporting.shared_objects import ObjectDecoder, ObjectEncoder


def test_terminal_ticket_releases_original_checkpoint_decoder():
    decoder = ObjectDecoder(
        ObjectEncoder().envelope(
            {
                "candidate": {
                    "id": "case",
                    "candidate_uid": "CAND_demo",
                    "validation_cluster_uid": "VAL_demo",
                    "function": "entry",
                    "category": "memory_leak",
                    "location": "a.c:3",
                    "evidence_pack": {
                        "positive_evidence": ["full original evidence"],
                        "nested": {"x": [1, 2]},
                    },
                },
                "other_checkpoint_facts": {"large": list(range(1000))},
            }
        )
    )
    previous = weakref.ref(decoder)
    issue = decoder.root["candidate"]
    ledger = CandidateLedger()
    ledger.restore_review_candidate(issue)
    assert ledger.mark_issue_terminal(issue, disposition="needs_review") == 1
    record = ledger.records()[0]
    assert record.ticket.evidence["nested"]["x"] == [1, 2]
    assert record.terminal_issue["evidence_pack"]["nested"]["x"] == [1, 2]
    del decoder, issue
    gc.collect()
    assert previous() is None, "The original ticket retains the entire checkpoint object table"


def test_ticket_and_outcome_keep_complete_independent_views_after_terminal():
    original = {
        "id": "one",
        "candidate_uid": "CAND_one",
        "validation_cluster_uid": "VAL_one",
        "category": "memory_leak",
        "function": "entry",
        "location": "a.c:3",
        "evidence_pack": {"nested": {"locations": [3, 8], "source": "full evidence"}},
    }
    ledger = CandidateLedger()
    ledger.restore_review_candidate(original)
    assert ledger.mark_issue_terminal(original, disposition="needs_review") == 1
    record = ledger.records()[0]
    assert record.ticket.evidence._decoder is record.terminal_issue._decoder
    record.ticket.evidence["nested"]["locations"].append(12)
    assert record.terminal_issue["evidence_pack"]["nested"]["locations"] == [3, 8]
    assert original["evidence_pack"]["nested"]["locations"] == [3, 8]
    original["evidence_pack"]["nested"]["source"] = "new caller evidence"
    assert record.terminal_issue["evidence_pack"]["nested"]["source"] == "full evidence"
    assert record.ticket.evidence["nested"]["source"] == "full evidence"


def test_separate_checkpoint_readers_share_one_pool_without_losing_sources():
    references = []
    ledger = CandidateLedger()
    for number in range(3):
        decoder = ObjectDecoder(
            ObjectEncoder().envelope(
                {
                    "candidate": {
                        "id": str(number),
                        "candidate_uid": "CAND_" + str(number),
                        "validation_cluster_uid": "VAL_" + str(number),
                        "category": "memory_leak",
                        "function": "entry",
                        "location": "a.c:3",
                        "description": str(number),
                        "evidence_pack": {
                            "full_facts": {"values": list(range(30))},
                            "origin": number,
                        },
                    },
                    "other": {"unrelated_to_this_candidate": number},
                }
            )
        )
        references.append(weakref.ref(decoder))
        issue = decoder.root["candidate"]
        ledger.restore_review_candidate(issue)
        assert ledger.mark_issue_terminal(issue, disposition="confirmed") == 1
        del decoder, issue
    gc.collect()
    assert all(reference() is None for reference in references)
    records = ledger.records()
    assert len(records) == 3
    assert len({id(record.ticket.evidence._decoder) for record in records}) == 1
    assert [record.ticket.evidence["origin"] for record in records] == [0, 1, 2]
    records[0].ticket.evidence["full_facts"]["values"][0] = 100
    assert records[1].ticket.evidence["full_facts"]["values"][0] == 0


def test_internal_tuple_evidence_retains_type_and_all_values():
    issue = {
        "id": "tuple",
        "candidate_uid": "CAND_tuple",
        "validation_cluster_uid": "VAL_tuple",
        "category": "memory_leak",
        "function": "entry",
        "location": "a.c:3",
        "evidence_pack": {"internal_tuple": (1, [2, 3])},
    }
    ledger = CandidateLedger()
    ledger.restore_review_candidate(issue)
    assert ledger.mark_issue_terminal(issue, disposition="needs_review") == 1
    record = ledger.records()[0]
    assert type(record.ticket.evidence["internal_tuple"]) is tuple
    assert record.ticket.evidence["internal_tuple"] == (1, [2, 3])
    issue["evidence_pack"]["internal_tuple"][1].append(4)
    assert record.ticket.evidence["internal_tuple"] == (1, [2, 3])
