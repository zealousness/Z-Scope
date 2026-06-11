"""Range benchmark-specific false-positive audit rules."""

from __future__ import annotations

from typing import Any, Dict

from zscope.benchmarking.protocol import (
    FP_AUDIT_DUPLICATE_OF_GT,
    FP_AUDIT_FALSE_POSITIVE_SUPPRESS,
    FP_AUDIT_NEEDS_REVIEW_ONLY,
    FP_AUDIT_TRUE_EXTRA_ADD_GT,
)


def classify_range_false_positive_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Classify an FP record using the curated Range benchmark audit policy."""

    identity = str(record.get("identity") or "").lower().replace("\\", "/")
    dedup_key = str(record.get("dedup_key") or "").lower().replace("\\", "/")
    candidate_source = str(record.get("candidate_source") or "").lower()
    text = f"{identity} {dedup_key}"

    classification = FP_AUDIT_NEEDS_REVIEW_ONLY
    reason = "unmatched finding should remain review-only until a human audit classifies it"

    suppress_patterns = (
        (
            "td_query_status",
            "api_contract_violation",
            "status query stub is not a concrete security defect",
        ),
        (
            "_safe_realloc",
            "memory_leak",
            "helper returning NULL does not lose the caller-owned original pointer by itself",
        ),
        (
            "_lock_read_wrapper",
            "api_contract_violation",
            "thin lock wrapper logs failures but has no standalone vulnerability path",
        ),
        (
            "_td_runtime_worker",
            ("file_descriptor_leak", "fd_leak"),
            "worker receives an externally-owned descriptor and does not establish close ownership",
        ),
        (
            "_runtime_activate_service_path",
            "container_unlink_free_after_unlock",
            "unlink-after-unlock race lacks a concrete retained-reader path and overlaps cleanup modeling noise",
        ),
    )
    for function_token, category_token, why in suppress_patterns:
        category_tokens = category_token if isinstance(category_token, tuple) else (category_token,)
        if function_token in text and any(token in text for token in category_tokens):
            classification = FP_AUDIT_FALSE_POSITIVE_SUPPRESS
            reason = why
            break

    if classification == FP_AUDIT_NEEDS_REVIEW_ONLY and (
        (
            ("_validate_task" in text or "_executor_validate_command" in text)
            and ("system(" in text or "system(full_command)" in text)
        )
        or (
            "_peer_publish_shared_session" in text
            and ("use_after_free" in text or "missing_refcount" in text)
        )
        or ("td_process_control_message" in text and "g_callback_entry" in text)
    ):
        classification = FP_AUDIT_DUPLICATE_OF_GT
        reason = "unmatched finding is another manifestation of an already matched root cause"

    if classification == FP_AUDIT_NEEDS_REVIEW_ONLY and (
        (
            "_net_send_data" in text
            and any(
                token in text
                for token in (
                    "sigpipe",
                    "busy_wait",
                    "busy_loop",
                    "integer_truncation",
                    "signed_unsigned",
                    "net_send_data_return_truncation",
                    "resource_lifecycle",
                    "resource_management",
                )
            )
        )
        or ("_lifecycle_send_status" in text and "data_race" in text)
        or ("_executor_process_file" in text and "path_traversal" in text)
        or ("_runtime_read_service_flag" in text and "memory_leak" in text)
        or (
            "_net_recv_data" in text
            and any(
                token in text
                for token in (
                    "integer_truncation",
                    "signed_unsigned",
                    "net_recv_data_return_truncation",
                )
            )
        )
    ):
        classification = FP_AUDIT_TRUE_EXTRA_ADD_GT
        reason = (
            "finding has process-impact evidence and should be reviewed as a possible GT "
            "addition, not suppressed"
        )

    if (
        candidate_source in {"needs_review", "audit_observation"}
        and classification == FP_AUDIT_TRUE_EXTRA_ADD_GT
    ):
        reason += "; currently kept out of default until GT review completes"

    audited = dict(record)
    audited["fp_audit_classification"] = classification
    audited["fp_audit_reason"] = reason
    return audited
