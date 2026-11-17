"""
Report generation for Z-SCOPE.
Handles conversion of analysis results to JSON and Markdown formats.
"""

import json
import datetime
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..common.defect_cwe_map import cwe_tokens
from .shared_objects import dataclass_dict


@dataclass
class Issue:
    """Represents a single defect or issue found during analysis."""

    id: str
    function: str
    location: str
    category: str  # functionality, reliability, performance, security
    subcategory: str
    description: str
    root_cause: str
    suggested_fix: str
    confidence: float
    impact_level: str  # low, medium, high, critical
    reasoning: Optional[str] = None
    code_snippet: Optional[str] = None
    validation_status: str = (
        "pending"  # pending, validated, needs_review, uncertain, unvalidated, rejected
    )
    validation_reasoning: Optional[str] = None
    llm_explanation: Optional[str] = None
    promotion_review_reason: Optional[str] = None
    protocol_assessment: Optional[Dict[str, Any]] = None
    needs_review_sub_state: Optional[str] = None
    review_disposition_reason: Optional[str] = None
    review_adjudication: Optional[Dict[str, Any]] = None
    review_fact_store: Optional[Dict[str, Any]] = None
    review_claim_checks: Optional[List[Dict[str, Any]]] = None
    review_checked_proof: Optional[Dict[str, Any]] = None
    review_conditional_risks: Optional[List[Dict[str, Any]]] = None
    review_macro_branches: Optional[List[Dict[str, Any]]] = None
    review_guard_coverage: Optional[Dict[str, Any]] = None
    review_checkpoint_id: Optional[str] = None
    review_priority_signal: Optional[str] = None
    review_v3_entry_pool: Optional[str] = None
    review_v3_objective: Optional[str] = None
    parent_candidate_uid: Optional[str] = None
    parent_candidate_uids: Optional[List[str]] = None
    related_generation: Optional[int] = None
    analysis_scope: Optional[str] = None
    trigger_condition: Optional[str] = None
    user_rebuttal: Optional[str] = None
    finding_kind: Optional[str] = None
    validator_verdict: Optional[str] = None
    cwe: Optional[str] = None
    cwes: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    source: Optional[str] = None
    sink: Optional[str] = None
    guard_analysis: Optional[str] = None
    exploit_scenario: Optional[str] = None
    positive_evidence: Optional[List[str]] = None
    negative_evidence: Optional[List[str]] = None
    blocking_negative_evidence: Optional[bool] = None
    candidate_id: Optional[str] = None
    candidate_source: Optional[str] = None
    defect_class: Optional[str] = None
    rule: Optional[str] = None
    evidence_pack: Optional[Dict[str, Any]] = None
    dedup_key: Optional[str] = None
    final_score: Optional[float] = None
    score_components: Optional[Dict[str, float]] = None
    evidence_refs: Optional[List[str]] = None
    run_id: Optional[str] = None
    rule_id: Optional[str] = None
    rule_engine: Optional[str] = None
    rule_revision: Optional[int] = None
    rule_source: Optional[str] = None
    rule_status: Optional[str] = None
    rule_catalog_version: Optional[int] = None
    rule_catalog_sha256: Optional[str] = None
    skill: Optional[str] = None
    candidate_kind: Optional[str] = None
    signal_source: Optional[str] = None
    native_rule_id: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    entry_function: Optional[str] = None
    sink_function: Optional[str] = None
    target_function: Optional[str] = None
    analyzed_from: Optional[str] = None
    reachable_from_entry: Optional[bool] = None
    internal_sink_lifted: Optional[bool] = None
    normalized_category: Optional[str] = None
    source_loc: Optional[str] = None
    sink_loc: Optional[str] = None
    call_path: Optional[List[str]] = None
    call_paths: Optional[List[List[str]]] = None
    duplicate_sources: Optional[List[Dict[str, Any]]] = None
    duplicate_count: Optional[int] = None
    alternate_evidence: Optional[List[Dict[str, Any]]] = None
    dedup_decision: Optional[Dict[str, Any]] = None
    dedup_decisions: Optional[List[Dict[str, Any]]] = None
    category_family: Optional[str] = None
    resource_signature: Optional[str] = None
    related_needs_review_observations: Optional[List[Dict[str, Any]]] = None
    path_constraints: Optional[List[str]] = None
    allocator_kind: Optional[str] = None
    owner_object: Optional[str] = None
    lockset: Optional[List[str]] = None
    thread_object: Optional[str] = None
    llm_model: Optional[str] = None
    prompt_hash: Optional[str] = None
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    latency_ms: Optional[int] = None
    human_disposition: Optional[str] = None
    time_to_review: Optional[float] = None
    time_to_fix: Optional[float] = None
    candidate_schema_version: Optional[str] = None
    candidate_uid: Optional[str] = None
    occurrence_uid: Optional[str] = None
    history_key: Optional[str] = None
    evidence_hash: Optional[str] = None
    run_issue_uid: Optional[str] = None
    candidate_disposition: Optional[str] = None
    evidence_completeness: Optional[str] = None
    evidence_sources: Optional[List[str]] = None
    entry_paths: Optional[List[List[str]]] = None
    obligation_uid: Optional[str] = None
    obligation_shape: Optional[str] = None
    decision_context_version: Optional[str] = None
    decision_fact_version: Optional[str] = None
    decision_fact_coverage: Optional[str] = None
    missing_fact_kinds: Optional[List[str]] = None
    candidate_promotion_eligible: Optional[bool] = None
    candidate_promotion_reason: Optional[str] = None
    candidate_promotion_terminal_status: Optional[str] = None
    decision_proof: Optional[Dict[str, Any]] = None
    promotion_reason: Optional[str] = None
    proof_provider: Optional[str] = None
    proof_coverage: Optional[str] = None
    deterministic_prevalidation_decision: Optional[str] = None
    validator_avoided: Optional[bool] = None
    evidence_completion_status: Optional[str] = None
    evidence_completion_terminal_status: Optional[str] = None
    validation_group_alias_count: Optional[int] = None
    validator_invocation_count: Optional[int] = None
    rejected_with_proof_count: Optional[int] = None
    cluster_fragmentation_count: Optional[int] = None
    attribution: Optional[Dict[str, Any]] = None
    model_verdict: Optional[str] = None
    policy_disposition: Optional[str] = None
    validator_result_pass: Optional[str] = None
    validator_pass_history: Optional[List[Dict[str, Any]]] = None
    validator_policy_outcome: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(
        cls, data: Dict[str, Any], context_function: str = "unknown", issue_index: int = 1
    ) -> "Issue":
        """Create an Issue from a dictionary, filtering out unknown fields and providing defaults."""
        valid_fields = {f.name for f in fields(cls)}

        # Mapping for common LLM field variations
        mapping = {
            "type": "category",
            "vulnerability_type": "subcategory",
            "impact": "impact_level",
            "severity": "impact_level",
            "file": "location",
        }

        filtered_data = {}
        for k, v in data.items():
            if k in valid_fields:
                filtered_data[k] = v
            if k in mapping and mapping[k] in valid_fields and mapping[k] not in filtered_data:
                # If we have a mapping and the target field isn't already filled
                filtered_data[mapping[k]] = v

        # Multi-CWE and multi-category labels tolerate scalar inputs from
        # older reports and LLM payloads.
        for field_name in ("cwes", "categories"):
            value = filtered_data.get(field_name)
            if isinstance(value, str):
                filtered_data[field_name] = [value] if value else []
            elif isinstance(value, (list, tuple)):
                filtered_data[field_name] = [str(item) for item in value if str(item)]

        # Ensure required fields have SOMETHING to avoid __init__ errors
        # These are the 9 fields mentioned in the error message + 'id'
        defaults = {
            "id": f"ISSUE_{issue_index}",
            "function": context_function,
            "location": "unknown:0",
            "category": "reliability",
            "subcategory": "general",
            "description": "No description provided",
            "reasoning": "No reasoning provided",
            "root_cause": "Unknown",
            "suggested_fix": "Review code",
            "confidence": 0.5,
            "impact_level": "medium",
        }

        for field_name, default_val in defaults.items():
            if field_name not in filtered_data or filtered_data[field_name] is None:
                filtered_data[field_name] = default_val
            elif field_name in [
                "id",
                "function",
                "location",
                "category",
                "subcategory",
                "description",
                "root_cause",
                "suggested_fix",
                "impact_level",
            ]:
                # Ensure these are strings
                if not isinstance(filtered_data[field_name], str):
                    filtered_data[field_name] = str(filtered_data[field_name])
            elif field_name == "confidence":
                try:
                    filtered_data[field_name] = float(filtered_data[field_name])
                except:
                    filtered_data[field_name] = 0.5

        return cls(**filtered_data)

    def to_dict(self) -> Dict[str, Any]:
        return dataclass_dict(self)


@dataclass
class FinalReport:
    """Represents the final analysis report."""

    entry_function: str
    overall_verdict: str  # no_issue_found, issues_found, insufficient_info
    issues: List[Issue] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    report_views: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = 2
    finding_status: str = "clean"
    completeness: str = "complete"
    scan_outcome: str = "clean"
    run_manifest: Dict[str, Any] = field(default_factory=dict)
    candidate_terminal_states: List[Dict[str, Any]] = field(default_factory=list)
    needs_review_governance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_function": self.entry_function,
            "overall_verdict": self.overall_verdict,
            "issues": [issue.to_dict() for issue in self.issues],
            "notes": self.notes,
            "metadata": self.metadata,
            "rule_catalog": self.metadata.get("rule_catalog", {}),
            "rule_candidate_counts": self.metadata.get("rule_candidate_counts", {}),
            "report_views": self.report_views,
            "schema_version": self.schema_version,
            "finding_status": self.finding_status,
            "completeness": self.completeness,
            "scan_outcome": self.scan_outcome,
            "run_manifest": self.run_manifest,
            "candidate_terminal_states": self.candidate_terminal_states,
            "needs_review_governance": self.needs_review_governance,
        }


class ReportGenerator:
    """Generates reports in various formats."""

    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)

    @staticmethod
    def _issue_cwe_labels(issue: Issue) -> List[str]:
        """Ordered CWE labels: the primary CWE first, then the full set."""

        ordered: List[str] = []
        for value in (issue.cwe, issue.cwes):
            for token in cwe_tokens(value):
                if token not in ordered:
                    ordered.append(token)
        return ordered

    @staticmethod
    def _normalize_md_text(value: Optional[str]) -> str:
        if value is None:
            return ""
        return str(value).replace("\\n", "\n")

    def save_json_report(self, report: FinalReport, filename: str = "report.json") -> Path:
        """Save report as JSON."""
        output_path = self.project_root / filename
        data = report.to_dict()
        from .json_io import write_report_atomic

        write_report_atomic(output_path, data)
        return output_path

    @staticmethod
    def _needs_review_issues(report: FinalReport) -> List[tuple]:
        """Project final needs_review items from the report view for Markdown.

        Returns ``(Issue, raw_dict)`` pairs so the Markdown renderer can also
        surface the plan Phase 3 review sub-state and presentation bundle,
        which the compact ``Issue`` projection does not carry.
        """
        review_statuses = {"needs_review", "uncertain", "unvalidated"}
        views = report.report_views if isinstance(report.report_views, dict) else {}
        view = views.get("with_needs_review")
        raw_items = view.get("issues", []) if isinstance(view, dict) else []
        projected: List[tuple] = []
        for index, raw in enumerate(raw_items, 1):
            if isinstance(raw, Issue):
                if str(raw.validation_status or "").strip().lower() in review_statuses:
                    projected.append((raw, {}))
                continue
            if not isinstance(raw, dict):
                continue
            status = str(raw.get("validation_status") or "").strip().lower()
            if not status:
                disposition = str(raw.get("candidate_disposition") or "").strip().lower()
                finding_kind = str(raw.get("finding_kind") or "").strip().lower()
                status = (
                    "needs_review"
                    if disposition == "needs_review" or finding_kind == "needs_review"
                    else ""
                )
            if status not in review_statuses:
                continue
            issue = Issue.from_dict(raw, context_function=report.entry_function, issue_index=index)
            issue.validation_status = "needs_review"
            projected.append((issue, raw))
        return projected

    def save_markdown_report(self, report: FinalReport) -> Path:
        """保存中文分析结论报告。"""
        from .artifact_reuse import artifact_reuse_markdown

        review_issues = self._needs_review_issues(report)
        md_content = f"""# Z-SCOPE 分析报告

**分析时间**: {report.metadata.get('timestamp', '未记录')}
**入口函数**: `{report.entry_function}`
**整体结论**: {self._translate_verdict(report.overall_verdict)}

## 缺陷摘要统计

"""
        md_content += (
            f"**Finding Status**: `{report.finding_status}`\n"
            f"**Completeness**: `{report.completeness}`"
            f"{' (incomplete)' if report.completeness != 'complete' else ''}\n\n"
        )
        md_content += artifact_reuse_markdown(report.metadata)
        if not report.issues:
            if review_issues:
                md_content += "未发现已确认缺陷；存在待复核项。\n"
            else:
                md_content += "未发现显著缺陷。\n"
        else:
            # Filter out rejected issues for offline report
            reportable_issues = [i for i in report.issues if i.validation_status != "rejected"]

            critical = sum(1 for i in reportable_issues if i.impact_level.lower() == "critical")
            high = sum(1 for i in reportable_issues if i.impact_level.lower() == "high")
            medium = sum(1 for i in reportable_issues if i.impact_level.lower() == "medium")
            low = sum(1 for i in reportable_issues if i.impact_level.lower() == "low")

            md_content += f"| 严重等级 | 数量 |\n| :--- | :--- |\n"
            md_content += f"| 🔴 Critical | {critical} |\n"
            md_content += f"| 🟠 High | {high} |\n"
            md_content += f"| 🟡 Medium | {medium} |\n"
            md_content += f"| 🔵 Low | {low} |\n\n"

            validated = sum(1 for i in reportable_issues if i.validation_status == "validated")
            md_content += f"**验证状态**: {validated} 已确认\n\n"

            md_content += "## 缺陷列表\n\n"
            for issue in reportable_issues:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
                    issue.impact_level.lower(), "⚪"
                )

                md_content += f"### {icon} [{issue.id}] {issue.category}: {issue.subcategory}\n"
                md_content += f"- **所在函数**: `{issue.function}`\n"
                md_content += f"- **代码位置**: `{issue.location}`\n"
                md_content += f"- **置信度**: {issue.confidence:.0%}\n"
                if issue.final_score is not None:
                    md_content += f"- **综合评分**: {issue.final_score:.0%}\n"
                cwe_labels = self._issue_cwe_labels(issue)
                if cwe_labels:
                    md_content += f"- **CWE**: {', '.join(cwe_labels)}\n"
                if issue.finding_kind:
                    md_content += f"- **Finding 类型**: `{issue.finding_kind}`\n"
                if issue.code_snippet:
                    md_content += f"\n**相关代码**:\n```c\n{self._normalize_md_text(issue.code_snippet)}\n```\n"
                md_content += f"\n**问题描述**:\n{self._normalize_md_text(issue.description)}\n"
                if issue.reasoning:
                    md_content += f"\n**分析推理**:\n{self._normalize_md_text(issue.reasoning)}\n"
                md_content += f"\n**根本原因**:\n{self._normalize_md_text(issue.root_cause)}\n"
                md_content += f"\n**修复建议**:\n> {self._normalize_md_text(issue.suggested_fix)}\n"

                if issue.validation_reasoning:
                    status_label = {
                        "validated": "✅ Validator 确认",
                        "needs_review": "🟡 Validator 待复核",
                        "uncertain": "🟠 Validator 证据不足",
                        "unvalidated": "⚪ Validator 未启用",
                        "pending": "⚪ Validator 未完成",
                        "rejected": "❌ Validator 否决",
                    }.get(issue.validation_status, "⚪ Validator 未完成")
                    md_content += f"\n**{status_label}**:\n{self._normalize_md_text(issue.validation_reasoning)}\n"

                if issue.llm_explanation:
                    md_content += (
                        "\n**🤖 决策解释**:\n" f"{self._normalize_md_text(issue.llm_explanation)}\n"
                    )

                if issue.promotion_review_reason:
                    md_content += (
                        "\n**未晋级为 validated 的原因**:\n"
                        f"{self._normalize_md_text(issue.promotion_review_reason)}\n"
                    )

                if issue.protocol_assessment:
                    md_content += "\n**对象协议确认的业务范围（扫描时）**:\n"
                    for assumption in issue.protocol_assessment.get("assumptions", []):
                        answer = assumption.get("answer") or {}
                        md_content += (
                            "- "
                            + self._normalize_md_text(assumption.get("statement", ""))
                            + "；来源："
                            + self._normalize_md_text(answer.get("source_note", "未确认"))
                            + "\n"
                        )

                if issue.user_rebuttal:
                    md_content += (
                        "\n**👤 用户反驳 / 复核说明**:\n"
                        f"{self._normalize_md_text(issue.user_rebuttal)}\n"
                    )

                md_content += "\n---\n"

        if review_issues:
            md_content += "\n## 待复核问题\n\n"
            sub_state_labels = {
                "model_uncertain": "模型未能判定",
                "model_rejected_unproven": "模型否决但未获确定性证明",
                "policy_pending_promotion": "证据完整，等待策略提升",
                "business_conditional": "条件性风险：业务前提待核实",
                "protocol_pending": "待补证：技术证据未闭合",
            }
            for issue, raw_review in review_issues:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
                    issue.impact_level.lower(), "⚪"
                )
                md_content += f"### {icon} [{issue.id}] {issue.category}: {issue.subcategory}\n"
                md_content += f"- **所在函数**: `{issue.function}`\n"
                md_content += f"- **代码位置**: `{issue.location}`\n"
                md_content += f"- **置信度**: {issue.confidence:.0%}\n"
                cwe_labels = self._issue_cwe_labels(issue)
                if cwe_labels:
                    md_content += f"- **CWE**: {', '.join(cwe_labels)}\n"
                if issue.finding_kind:
                    md_content += f"- **Finding 类型**: `{issue.finding_kind}`\n"
                if issue.code_snippet:
                    md_content += f"\n**相关代码**:\n```c\n{self._normalize_md_text(issue.code_snippet)}\n```\n"
                md_content += f"\n**问题描述**:\n{self._normalize_md_text(issue.description)}\n"
                if issue.reasoning:
                    md_content += f"\n**分析推理**:\n{self._normalize_md_text(issue.reasoning)}\n"
                md_content += f"\n**根本原因**:\n{self._normalize_md_text(issue.root_cause)}\n"
                md_content += f"\n**修复建议**:\n> {self._normalize_md_text(issue.suggested_fix)}\n"
                if issue.validation_reasoning:
                    md_content += (
                        "\n**🟡 Validator 待复核**:\n"
                        f"{self._normalize_md_text(issue.validation_reasoning)}\n"
                    )
                if issue.llm_explanation:
                    md_content += (
                        "\n**🤖 决策解释**:\n" f"{self._normalize_md_text(issue.llm_explanation)}\n"
                    )
                review_presentation = (
                    raw_review.get("needs_review_presentation")
                    if isinstance(raw_review, dict)
                    else None
                )
                sub_state = (
                    str(raw_review.get("needs_review_sub_state") or "")
                    if isinstance(raw_review, dict)
                    else ""
                )
                if sub_state:
                    label = sub_state_labels.get(sub_state, sub_state)
                    md_content += f"\n**复核子状态**: `{sub_state}`（{label}）\n"
                if issue.promotion_review_reason:
                    md_content += (
                        "\n**未晋级为 validated 的原因**:\n"
                        f"{self._normalize_md_text(issue.promotion_review_reason)}\n"
                    )
                if isinstance(review_presentation, dict):
                    for assumption in review_presentation.get("business_assumptions", []):
                        md_content += (
                            "\n- **业务前提（未确认）**: "
                            + self._normalize_md_text(assumption.get("statement", ""))
                            + "\n"
                        )
                    for gap in review_presentation.get("technical_gaps", []):
                        md_content += "- **技术缺口**: " + self._normalize_md_text(gap) + "\n"
                    missing_kinds = review_presentation.get("missing_fact_kinds") or []
                    if missing_kinds:
                        md_content += (
                            "- **缺失事实清单**: "
                            + ", ".join(f"`{kind}`" for kind in missing_kinds)
                            + "\n"
                        )
                    action = str(review_presentation.get("suggested_action") or "").strip()
                    if action:
                        md_content += f"- **建议动作**: {self._normalize_md_text(action)}\n"
                if issue.user_rebuttal:
                    md_content += (
                        "\n**👤 用户反驳 / 复核说明**:\n"
                        f"{self._normalize_md_text(issue.user_rebuttal)}\n"
                    )
                md_content += "\n---\n"

        if report.notes:
            md_content += "\n## 分析备注\n"
            for note in report.notes:
                md_content += f"- {note}\n"

        path = self.project_root / "report.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(md_content)
        return path

    def _translate_verdict(self, verdict: str) -> str:
        translations = {
            "issues_found": "🔴 发现缺陷",
            "no_issue_found": "🟢 未发现明显问题",
            "insufficient_info": "🟡 信息不足，无法下定论",
        }
        return translations.get(verdict, verdict)
