"""LLM supplement that explains LLM-free deterministic validation decisions.

Deterministic prevalidation exists to save Validator tokens: complete
decision proofs close a candidate without any model involvement.  The
resulting ``validation_reasoning`` is a terse machine-shaped summary, so
users may not understand *why* the engine confirmed an issue or filed an
audit observation.  This module optionally asks the LLM to add one
user-facing Chinese explanation (``llm_explanation``) on top of the
decision.

Hard invariants:
- The deterministic verdict, disposition, and ``validation_reasoning``
  stay authoritative and are never modified; the LLM only appends the
  ``llm_explanation`` field.
- The pass is budget-capped per scan and degrades silently when no LLM
  client is available (for example the Validator is disabled).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from ...common.utils import extract_json_blocks

logger = logging.getLogger(__name__)

_EXPLANATION_TRACE_AGENT = "decision_explainer"
_EXPLANATION_TRACE_LABEL = "explain_deterministic_decision"

_DISPOSITION_CONFIRMED = "confirmed"
_DISPOSITION_AUDIT_OBSERVATION = "audit_observation"
_DISPOSITION_EVIDENCE_CONFLICT = "evidence_conflict"

_DESCRIPTION_LIMIT = 400
_DETERMINISTIC_SUMMARY_LIMIT = 600
_FACT_SUMMARY_LIMIT = 200
_CODE_EXCERPT_LIMIT = 1500
_EXPLANATION_MAX_CHARS = 800
_MAX_EVIDENCE_FACTS = 6

_SYSTEM_PROMPT = (
    "你是 Z-Scope 静态分析引擎的用户解释助手。引擎已经通过确定性证据完成验证并给出结论，"
    "你的任务是面向使用中文的安全审计人员解释这个结论。要求：\n"
    "1. 只做解释，不得修改、质疑或推翻给定的验证结论。\n"
    "2. 用 2-4 句话说明：这是什么问题；确定性证据为什么支持该结论；建议用户如何复核或处置。\n"
    "3. 全文使用简体中文；文件路径、函数名、符号与证据编号保持原样。\n"
    '4. 只输出一个 JSON 对象：{"explanation": "..."}，不要输出其他内容。'
)


def _truncate(text: Any, limit: int) -> str:
    value = str(text or "").strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + "…"


def decision_disposition(issue: Dict[str, Any]) -> Optional[str]:
    """Return the LLM-free disposition an explanation may target, else ``None``.

    Only decisions that the user actually sees in a report bucket qualify:
    confirmed-by-proof findings, static audit observations, and evidence
    conflicts.  Rejected-with-proof and shadow candidates are dropped from
    the report, so spending explanation tokens on them would be wasted.
    Issues that already carry an ``llm_explanation`` are skipped so the
    pass stays idempotent across validation batches.
    """

    if not isinstance(issue, dict) or str(issue.get("llm_explanation") or "").strip():
        return None
    deterministic = str(issue.get("deterministic_prevalidation_decision") or "").strip().lower()
    if deterministic == "confirmed":
        return _DISPOSITION_CONFIRMED
    if deterministic == "evidence_conflict":
        return _DISPOSITION_EVIDENCE_CONFLICT
    finding_kind = str(issue.get("finding_kind") or "").strip().lower()
    rejection_source = str(issue.get("rejection_source") or "").strip().lower()
    if rejection_source == "static_analysis" and finding_kind == "audit_observation":
        return _DISPOSITION_AUDIT_OBSERVATION
    return None


def collect_unexplained_decisions(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect report-visible LLM-free decisions that lack an explanation."""

    collected: List[Dict[str, Any]] = []
    for bucket in ("issues", "observations"):
        value = state.get(bucket)
        if not isinstance(value, list):
            continue
        for issue in value:
            disposition = decision_disposition(issue) if isinstance(issue, dict) else None
            if disposition:
                collected.append(issue)
    return collected


def _evidence_fact_summaries(proof: Dict[str, Any]) -> List[str]:
    raw_facts = proof.get("facts")
    if not isinstance(raw_facts, list):
        return []
    summaries: List[str] = []
    for fact in raw_facts[:_MAX_EVIDENCE_FACTS]:
        if isinstance(fact, dict):
            summary = str(fact.get("summary") or fact.get("kind") or "")
        else:
            summary = str(fact)
        summary = _truncate(summary, _FACT_SUMMARY_LIMIT)
        if summary:
            summaries.append(summary)
    return summaries


def _decision_payload(issue: Dict[str, Any], disposition: str) -> Dict[str, Any]:
    proof = issue.get("decision_proof")
    proof = proof if isinstance(proof, dict) else {}
    deterministic_summary = str(proof.get("summary") or "").strip()
    if not deterministic_summary:
        deterministic_summary = str(issue.get("validation_reasoning") or "").strip()
    return {
        "disposition": disposition,
        "category": str(issue.get("category") or issue.get("defect_class") or ""),
        "subcategory": str(issue.get("subcategory") or ""),
        "cwe": str(issue.get("cwe") or ""),
        "function": str(issue.get("function") or ""),
        "location": str(issue.get("location") or ""),
        "description": _truncate(issue.get("description"), _DESCRIPTION_LIMIT),
        "deterministic_summary": _truncate(deterministic_summary, _DETERMINISTIC_SUMMARY_LIMIT),
        "evidence_facts": _evidence_fact_summaries(proof),
        "code_excerpt": _truncate(issue.get("code"), _CODE_EXCERPT_LIMIT),
    }


def _decision_user_prompt(payload: Dict[str, Any]) -> str:
    return "请为以下确定性验证决策生成用户可读的中文解释，只返回 JSON。\n" + json.dumps(
        payload, ensure_ascii=False, indent=2
    )


def explain_decision_with_llm(
    llm_client: Any,
    issue: Dict[str, Any],
    *,
    disposition: Optional[str] = None,
) -> Optional[str]:
    """Ask the LLM for one Chinese explanation of a deterministic decision.

    Returns ``None`` on any failure (no client, transport error, unusable
    output); the caller leaves the issue untouched in that case.
    """

    if llm_client is None:
        return None
    disposition = disposition or decision_disposition(issue)
    if not disposition:
        return None
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": _decision_user_prompt(_decision_payload(issue, disposition))},
    ]
    try:
        response = llm_client.chat_completion(
            messages,
            temperature=0.0,
            max_tokens=600,
            trace_agent=_EXPLANATION_TRACE_AGENT,
            trace_label=_EXPLANATION_TRACE_LABEL,
        )
    except Exception as exc:
        logger.debug("[decision-explanation] LLM call failed: %s", exc)
        return None
    try:
        choice = (response.get("choices") or [{}])[0]
        content = str((choice.get("message") or {}).get("content") or "")
    except Exception:
        content = ""
    for block in extract_json_blocks(content):
        explanation = str(block.get("explanation") or "").strip()
        if explanation:
            return explanation[:_EXPLANATION_MAX_CHARS]
    return None


def apply_decision_explanations(
    state: Dict[str, Any],
    *,
    llm_client: Any,
    budget: int,
    used: int = 0,
) -> Dict[str, int]:
    """Attach ``llm_explanation`` to eligible report-visible decisions.

    ``used`` carries the scan-wide explanation budget already spent; the
    returned stats report how many issues were newly explained so callers
    can keep the counter across validation batches.  Deterministic texts
    are never modified, and any failure leaves the issue unchanged.
    """

    stats = {"candidates": 0, "explained": 0, "skipped_budget": 0, "failed": 0}
    if llm_client is None or budget <= 0:
        return stats
    remaining = max(0, int(budget) - max(0, int(used)))
    issues = collect_unexplained_decisions(state)
    stats["candidates"] = len(issues)
    if not issues:
        return stats
    for issue in issues:
        if remaining <= 0:
            stats["skipped_budget"] += 1
            continue
        explanation = explain_decision_with_llm(llm_client, issue)
        if explanation:
            issue["llm_explanation"] = explanation
            stats["explained"] += 1
            remaining -= 1
        else:
            stats["failed"] += 1
    return stats
