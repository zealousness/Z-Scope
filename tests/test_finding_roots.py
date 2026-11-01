from zscope.reporting.finding_roots import project_finding_roots


def _outcome(
    uid: str,
    *,
    subject: str = "owner.member",
    region: str = "REGION_cfg_exit_42",
    code_hash: str = "code-a",
    proof_kind: str = "missing_cleanup_path",
    disposition: str = "confirmed",
) -> dict:
    return {
        "candidate_uid": f"CAND_{uid}",
        "validation_cluster_uid": f"VAL_{uid}",
        "occurrence_uid": f"OCC_{uid}",
        "candidate_disposition": disposition,
        "defect_class": "memory_leak",
        "file_path": "src\\owner.c",
        "function": "destroy_owner",
        "obligation_shape": "source_centric",
        "code_hash": code_hash,
        "security_obligation": {
            "subject_uid": subject,
            "decision_region_uid": region,
        },
        "decision_proof": {
            "outcome": "confirm",
            "proof_kind": proof_kind,
            "proof_version": "zscope.decision-proof.v4",
            "producer_engine": "cfg",
            "fact_ids": ["fact:1", "fact:2"],
            "cfg_nodes": ["42"],
            "subject_identity": subject,
            "code_hash": code_hash,
            "scope": "complete cleanup path",
            "completeness": "complete",
        },
    }


def test_composite_cleanup_root_keeps_alias_terminal_and_subjects() -> None:
    projection = project_finding_roots(
        [_outcome("a", subject="owner.left"), _outcome("b", subject="owner.right")]
    )

    primary = [
        item
        for item in projection.outcomes
        if item["candidate_disposition"] == "confirmed"
    ]
    aliases = [
        item
        for item in projection.outcomes
        if item["candidate_disposition"] == "deduplicated_alias"
    ]
    assert len(primary) == 1
    assert len(aliases) == 1
    assert primary[0]["affected_subjects"] == ["owner.left", "owner.right"]
    assert primary[0]["occurrence_uids"] == ["OCC_a", "OCC_b"]
    assert aliases[0]["finding_root_uid"] == primary[0]["finding_root_uid"]


def test_different_guard_region_or_code_hash_never_merges() -> None:
    projection = project_finding_roots(
        [
            _outcome("a"),
            _outcome("b", region="REGION_cfg_exit_43"),
            _outcome("c", code_hash="code-b"),
        ]
    )

    assert projection.finding_root_count == 3
    assert projection.finding_root_alias_count == 0


def test_non_composite_proof_keeps_distinct_objects() -> None:
    projection = project_finding_roots(
        [
            _outcome("a", subject="left", proof_kind="unguarded_source_to_sink"),
            _outcome("b", subject="right", proof_kind="unguarded_source_to_sink"),
        ]
    )

    assert projection.finding_root_count == 2
    assert projection.finding_root_alias_count == 0


def test_review_requires_identical_decision_evidence_and_context() -> None:
    first = _outcome("a", disposition="needs_review")
    second = _outcome("b", disposition="needs_review")
    for item in (first, second):
        item.pop("decision_proof")
        item["decision_evidence_hash"] = "evidence-a"
        item["context_signature"] = "context-a"
    projection = project_finding_roots([first, second])

    assert projection.finding_root_count == 1
    assert projection.finding_root_alias_count == 1


def _publication_outcome(
    uid: str,
    *,
    sink_line: int = 23,
    sink_operation: str = "registry.head = entry;",
    code: str = """\
20 | Entry *entry = allocate_entry();
22 | LOCK(&registry.lock);
23 | registry.head = entry;
24 | entry->value = duplicate(value);
25 | if (!entry->value) {
26 |     UNLOCK(&registry.lock);
27 |     return -1;
28 | }
29 | entry->state = READY;
""",
    deterministic: bool = False,
    blocking_negative_evidence: bool = False,
) -> dict:
    outcome = {
        "candidate_uid": f"CAND_pub_{uid}",
        "validation_cluster_uid": f"VAL_pub_{uid}",
        "occurrence_uid": f"OCC_pub_{uid}",
        "candidate_disposition": "confirmed",
        "defect_class": "object_publication",
        "file_path": "src\\registry.c",
        "function": "publish_entry",
        "obligation_shape": "sink_sensitive",
        "blocking_negative_evidence": blocking_negative_evidence,
        "code_snippet": code,
        "security_obligation": {
            "defect_family": "object_publication",
            "obligation_shape": "sink_sensitive",
            "subject_uid": "entry",
            "sink_uid": {
                "file": "src/registry.c",
                "line": sink_line,
                "operation": sink_operation,
            },
            "decision_region_uid": f"REGION_detector_{uid}",
        },
        "decision_proof": {},
    }
    if deterministic:
        outcome["decision_proof"] = {
            "outcome": "confirm",
            "proof_kind": "ordered_publication_before_initialization",
            "proof_version": "zscope.decision-proof.v4",
            "producer_engine": "publication_order_prover",
            "fact_ids": ["cfg:20:allocation", "cfg:23:publish", "cfg:29:late_init"],
            "cfg_nodes": ["20", "23", "29"],
            "subject_identity": "entry",
            "code_hash": "code-publication",
            "scope": "complete publication lifecycle",
            "completeness": "complete",
        }
    return outcome


def test_exact_publication_sink_attaches_confirmed_observation_to_proved_root() -> None:
    projection = project_finding_roots(
        [
            _publication_outcome("graph", deterministic=True),
            _publication_outcome("clang"),
        ]
    )

    primary = [
        item for item in projection.outcomes if item["candidate_disposition"] == "confirmed"
    ]
    aliases = [
        item
        for item in projection.outcomes
        if item["candidate_disposition"] == "deduplicated_alias"
    ]
    assert len(primary) == 1
    assert len(aliases) == 1
    assert primary[0]["candidate_uid"] == "CAND_pub_graph"
    assert primary[0]["finding_root_alias_uids"] == ["CAND_pub_clang"]
    assert primary[0]["occurrence_uids"] == ["OCC_pub_clang", "OCC_pub_graph"]


def test_attachment_updates_its_own_primary_when_another_bucket_is_processed() -> None:
    first_primary = _publication_outcome("first", deterministic=True)
    first_review = _publication_outcome("first-review")
    first_review["candidate_disposition"] = "needs_review"
    first_review["security_obligation"]["decision_region_uid"] = first_primary[
        "security_obligation"
    ]["decision_region_uid"]
    # Sort after the first attachment signature so the loop-local `primary`
    # from another bucket cannot receive the first group's root labels.
    later_primary = _publication_outcome(
        "later",
        sink_line=80,
        sink_operation="zz_registry.head = entry;",
        deterministic=True,
    )
    later_review = _publication_outcome(
        "later-review",
        sink_line=80,
        sink_operation="zz_registry.head = entry;",
    )
    later_review["candidate_disposition"] = "needs_review"
    later_review["security_obligation"]["decision_region_uid"] = later_primary[
        "security_obligation"
    ]["decision_region_uid"]

    projection = project_finding_roots(
        [first_primary, first_review, later_primary, later_review]
    )
    by_uid = {item["candidate_uid"]: item for item in projection.outcomes}

    assert by_uid["CAND_pub_first"]["candidate_disposition"] == "confirmed"
    assert by_uid["CAND_pub_first"]["finding_root_alias_uids"] == [
        "CAND_pub_first-review"
    ]
    assert by_uid["CAND_pub_first-review"]["finding_root_primary_candidate_uid"] == (
        "CAND_pub_first"
    )
    assert by_uid["CAND_pub_later"]["finding_root_alias_uids"] == [
        "CAND_pub_later-review"
    ]


def test_exact_publication_sink_does_not_merge_different_sink_or_code() -> None:
    different_code = """\
20 | Entry *entry = allocate_entry();
23 | registry.head = entry;
24 | entry->state = READY;
"""
    projection = project_finding_roots(
        [
            _publication_outcome("anchor", deterministic=True),
            _publication_outcome("other-sink", sink_line=24),
            _publication_outcome("other-code", code=different_code),
        ]
    )

    assert projection.finding_root_count == 3
    assert projection.finding_root_alias_count == 0


def test_exact_publication_sink_requires_deterministic_anchor_and_no_counterproof() -> None:
    no_anchor = project_finding_roots(
        [_publication_outcome("a"), _publication_outcome("b")]
    )
    blocked = project_finding_roots(
        [
            _publication_outcome("anchor", deterministic=True),
            _publication_outcome("blocked", blocking_negative_evidence=True),
        ]
    )

    assert no_anchor.finding_root_count == 2
    assert no_anchor.finding_root_alias_count == 0
    assert blocked.finding_root_count == 2
    assert blocked.finding_root_alias_count == 0
