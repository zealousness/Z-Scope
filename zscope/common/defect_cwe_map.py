"""Central defect-class -> CWE mapping for Z-SCOPE.

This module is the single authority for the CWE tag set that a defect class
carries when a finding has no richer per-rule declaration.  An issue may
therefore belong to multiple CWEs: the ordered tuple always starts with the
governance primary (the builtin rule catalog's ``cwe``) followed by the
additional CWEs that the class genuinely covers.

Curation policy:

* The first entry is the catalog's authoritative ``cwe`` for the class (or the
  SVF/validator/legacy mapping value for backend-only classes).
* Additional entries are limited to CWEs the defect class factually covers
  (for example ``memory_leak`` covers both CWE-401 and CWE-772).
* Generic umbrella CWEs (CWE-664, CWE-20, CWE-682) appear only for the
  specific classes that already declare them; they are never mass-applied
  across families.
* ``security_review`` is the generic observation fallback used by the report
  assembler and maps to CWE-693 so that every report-visible finding carries
  at least one CWE.

The mapping deliberately does not import :mod:`zscope.common.issue_identity`
so that identity utilities may consume it without a cycle.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


DEFECT_CLASS_CWES: Mapping[str, Tuple[str, ...]] = {
    # --- memory lifecycle -------------------------------------------------
    "memory_leak": ("CWE-401", "CWE-772"),
    "resource_leak": ("CWE-772",),
    "fd_leak": ("CWE-775",),
    "file_descriptor_leak": ("CWE-775",),
    "missing_fd_release": ("CWE-775",),
    "partial_resource_leak": ("CWE-401",),
    "thread_cache_leak": ("CWE-772",),
    "optimization_resource_lifecycle": ("CWE-772",),
    "incomplete_cleanup": ("CWE-401", "CWE-459"),
    "missing_refcount": ("CWE-772",),
    "realloc_misuse": ("CWE-401",),
    "alloc_free_mismatch": ("CWE-762",),
    "double_free": ("CWE-415",),
    "invalid_free": ("CWE-590", "CWE-761", "CWE-762"),
    "use_after_free": ("CWE-416",),
    "expired_pointer": ("CWE-825",),
    "stale_pointer": ("CWE-825",),
    "premature_destroy": ("CWE-416",),
    "memory_safety": ("CWE-664",),
    # --- allocation limits and exhaustion ---------------------------------
    "resource_allocation_without_limits": ("CWE-770",),
    "fd_allocation_without_limits": ("CWE-774",),
    "unchecked_allocation": ("CWE-690",),
    "excessive_allocation": ("CWE-789",),
    "resource_exhaustion": ("CWE-400",),
    "log_amplification": ("CWE-400",),
    # --- bounds -------------------------------------------------------------
    "bounds": ("CWE-125", "CWE-129", "CWE-120"),
    "buffer_overread": ("CWE-126",),
    "buffer_underread": ("CWE-127",),
    "buffer_underwrite": ("CWE-124",),
    "buffer_underflow": ("CWE-127",),
    "buffer_overflow": ("CWE-787",),
    "heap_overflow": ("CWE-122",),
    "out_of_bounds_write": ("CWE-787",),
    "out_of_range_pointer_offset": ("CWE-823",),
    "off_by_one": ("CWE-193",),
    "size_limit_mismatch": ("CWE-131",),
    "stack_overflow": ("CWE-121",),
    "untrusted_pointer": ("CWE-822",),
    "uninitialized_pointer": ("CWE-824",),
    "alignment": ("CWE-704",),
    # --- integer and numeric ------------------------------------------------
    "integer_overflow": ("CWE-190",),
    "integer_truncation": ("CWE-197",),
    "signed_unsigned": ("CWE-195",),
    "byte_order_logic": ("CWE-682",),
    "key_truncation": ("CWE-187",),
    # --- concurrency ---------------------------------------------------------
    "race": ("CWE-362",),
    "data_race": ("CWE-362",),
    "race_condition": ("CWE-362",),
    "shared_memory_race": ("CWE-362",),
    "shared_state_race": ("CWE-362",),
    "refcount_race": ("CWE-362",),
    "dynamic_array_race": ("CWE-362",),
    "reader_state_race": ("CWE-362",),
    "global_mode_race": ("CWE-362",),
    "registration_race": ("CWE-362",),
    "slot_race": ("CWE-362",),
    "key_generation_race": ("CWE-362",),
    "signal_race": ("CWE-479",),
    "signal_handler_unsafe": ("CWE-479",),
    "callback_self_destroy_race": ("CWE-416", "CWE-362"),
    "check_then_act_race": ("CWE-362",),
    "double_checked_locking": ("CWE-362",),
    "toctou": ("CWE-367",),
    "object_publication": ("CWE-362",),
    "unsynchronized_shared_state": ("CWE-362", "CWE-567"),
    "concurrency_race": ("CWE-362",),
    # --- locks and deadlock ---------------------------------------------------
    "deadlock": ("CWE-833",),
    "signal_deadlock": ("CWE-833",),
    "lock_order_deadlock": ("CWE-833",),
    "missing_unlock": ("CWE-667",),
    "unlock_without_lock": ("CWE-832",),
    "lock_protocol_violation": ("CWE-832",),
    "held_lock_callback": ("CWE-667",),
    "lost_wakeup": ("CWE-366",),
    # --- injection and input validation --------------------------------------
    "command_injection": ("CWE-78",),
    "code_injection": ("CWE-94",),
    "template_injection": ("CWE-94",),
    "jndi_injection": ("CWE-74",),
    "reflection_injection": ("CWE-470",),
    "dynamic_class_loading": ("CWE-470",),
    "sql_injection": ("CWE-89",),
    "jpa_injection": ("CWE-89",),
    "nosql_injection": ("CWE-943",),
    "xpath_injection": ("CWE-643",),
    "ldap_injection": ("CWE-90",),
    "path_traversal": ("CWE-22",),
    "open_redirect": ("CWE-601",),
    "ssrf": ("CWE-918",),
    "xxe": ("CWE-611",),
    "xss": ("CWE-79",),
    "header_injection": ("CWE-113",),
    "format_string": ("CWE-134",),
    "file_type_validation": ("CWE-20",),
    "incorrect_validation_order": ("CWE-20",),
    "protocol_validation": ("CWE-20",),
    "version_filtering": ("CWE-20",),
    "unsafe_deserialization": ("CWE-502",),
    "file_upload": ("CWE-434",),
    "temp_file_risk": ("CWE-377",),
    "incomplete_input_validation": ("CWE-20",),
    "incomplete_security_filter": ("CWE-20",),
    "insufficient_validation": ("CWE-20",),
    # --- crypto and authorization ---------------------------------------------
    "crypto_misuse": ("CWE-329",),
    "weak_crypto": ("CWE-327",),
    "weak_random": ("CWE-338",),
    "insecure_tls": ("CWE-295",),
    "jwt_misuse": ("CWE-347",),
    "secret_exposure": ("CWE-798",),
    "sensitive_info_exposure": ("CWE-200",),
    "sensitive_log": ("CWE-532",),
    "insecure_cookie": ("CWE-614",),
    "cors_misconfiguration": ("CWE-942",),
    "authz_bypass": ("CWE-862", "CWE-639"),
    "permission": ("CWE-732",),
    "insecure_file_permission": ("CWE-732",),
    # --- type, protocol and machine state --------------------------------------
    "type_confusion": ("CWE-843",),
    "protocol_mixup": ("CWE-346",),
    "fd_type_mismatch": ("CWE-628",),
    "fd_encoding_mismatch": ("CWE-587",),
    "semantic_mismatch": ("CWE-628",),
    "api_contract_violation": ("CWE-628",),
    "state_inconsistency": ("CWE-672",),
    "state_machine": ("CWE-672",),
    "stale_fd": ("CWE-672",),
    "sigpipe_unhandled": ("CWE-404",),
    "busy_loop": ("CWE-835",),
    "infinite_loop": ("CWE-835",),
    "busy_wait_loop": ("CWE-835",),
    "spin_loop": ("CWE-835",),
    "unchecked_return": ("CWE-252",),
    "bad_parameter_or_api_misuse": ("CWE-252",),
    "uninitialized_read": ("CWE-457",),
    "uninitialized_output": ("CWE-457",),
    "null_pointer_dereference": ("CWE-476",),
    "logic_error": ("CWE-682",),
    "stack_escape": ("CWE-562",),
    "regex_dos": ("CWE-1333",),
    # --- generic report fallback ------------------------------------------------
    "security_review": ("CWE-693",),
}

_CATEGORY_KEY_ALIASES: Mapping[str, str] = {
    "buffer_over_read": "buffer_overread",
    "buffer_under_read": "buffer_underread",
    "buffer_under_write": "buffer_underwrite",
    "file_descriptor_leak": "fd_leak",
}

_CWE_FULL_RE = re.compile(r"CWE-[1-9][0-9]*\Z")
_CWE_SCAN_RE = re.compile(r"CWE[-_ ]?(\d{1,6})", re.IGNORECASE)
_CATEGORY_KEY_RE = re.compile(r"[^a-z0-9]+")

__all__ = [
    "DEFECT_CLASS_CWES",
    "cwe_tokens",
    "cwes_for_category",
    "ensure_issue_cwes",
    "issue_category_cwes",
    "issue_category_tokens",
    "merge_cwes",
    "normalize_cwe",
]


def normalize_cwe(value: Any) -> str:
    """Return the canonical ``CWE-<id>`` spelling of a scalar, or ``""``."""

    text = str(value or "").strip().upper()
    return text if _CWE_FULL_RE.fullmatch(text) else ""


def cwe_tokens(value: Any) -> List[str]:
    """Extract every ``CWE-<id>`` token from a scalar, list, or compound text.

    Compound label strings such as ``"CWE-362/CWE-416"`` yield both tokens,
    the same way downstream consumers parse slash-separated CWE labels.
    """

    items: List[Any] = list(value) if isinstance(value, (list, tuple, set)) else [value]
    tokens: List[str] = []
    for item in items:
        direct = normalize_cwe(item)
        if direct:
            tokens.append(direct)
            continue
        for match in _CWE_SCAN_RE.finditer(str(item or "")):
            tokens.append(f"CWE-{int(match.group(1))}")
    return tokens


def merge_cwes(*groups: Optional[Iterable[Any]]) -> List[str]:
    """Order-preserving dedupe union of CWE groups (first occurrence wins).

    ``None`` groups (missing fields) are ignored, so callers can pass issue
    label fields directly without guarding.
    """

    merged: List[str] = []
    for group in groups:
        if group is None:
            continue
        for token in cwe_tokens(group):
            if token not in merged:
                merged.append(token)
    return merged


def _category_key(category: Any) -> str:
    return _CATEGORY_KEY_RE.sub("_", str(category or "").strip().lower()).strip("_")


def cwes_for_category(category: Any) -> Tuple[str, ...]:
    """Return the ordered CWE tuple for a defect class token."""

    key = _category_key(category)
    if not key:
        return ()
    direct = DEFECT_CLASS_CWES.get(key)
    if direct:
        return direct
    return DEFECT_CLASS_CWES.get(_CATEGORY_KEY_ALIASES.get(key, ""), ())


def issue_category_tokens(issue: Mapping[str, Any]) -> List[str]:
    """Ordered unique category-ish tokens declared by an issue mapping."""

    values: List[Any] = [
        issue.get("defect_class"),
        issue.get("category"),
        issue.get("subcategory"),
        issue.get("normalized_category"),
    ]
    pack = issue.get("evidence_pack")
    if isinstance(pack, Mapping):
        values.extend((pack.get("defect_class"), pack.get("defect_family")))
        nested = pack.get("security_obligation")
        if isinstance(nested, Mapping):
            values.append(nested.get("defect_family"))
    tokens: List[str] = []
    for value in values:
        key = _category_key(value)
        if key and key not in tokens:
            tokens.append(key)
    return tokens


def issue_category_cwes(issue: Mapping[str, Any]) -> List[str]:
    """CWEs derivable from an issue's declared categories."""

    cwes: List[str] = []
    for token in issue_category_tokens(issue):
        for cwe in cwes_for_category(token):
            if cwe not in cwes:
                cwes.append(cwe)
    return cwes


def ensure_issue_cwes(issue: Dict[str, Any]) -> List[str]:
    """Guarantee a non-empty ``cwes`` list whenever the issue is classifiable.

    The ordered union starts with the issue's primary ``cwe`` (so
    ``issue["cwe"] == issue["cwes"][0]`` always holds afterwards), then any
    explicit ``cwes`` entries, then the CWEs derived from the issue's
    categories.  When ``cwe`` is missing it is backfilled from the first
    union entry.  Issues with neither CWEs nor a known category keep their
    previous state (no invented CWE).  The same list is mirrored into
    ``evidence_pack["cwes"]`` when the issue carries an evidence pack.
    """

    primary = normalize_cwe(issue.get("cwe"))
    ordered = merge_cwes(
        [primary] if primary else [], issue.get("cwes"), issue_category_cwes(issue)
    )
    if not ordered:
        return list(issue.get("cwes") or [])
    issue["cwes"] = ordered
    if not primary:
        issue["cwe"] = ordered[0]
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        pack["cwes"] = list(ordered)
    return ordered
