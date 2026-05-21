"""
Report generation for Z-SCOPE.
Handles conversion of analysis results to JSON and Markdown formats.
"""

import json
import datetime
from dataclasses import dataclass, asdict, field, fields
from pathlib import Path
from typing import List, Dict, Any, Optional


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
    validation_status: str = "pending" # pending, validated, needs_review, uncertain, unvalidated, rejected
    validation_reasoning: Optional[str] = None
    finding_kind: Optional[str] = None
    validator_verdict: Optional[str] = None
    cwe: Optional[str] = None
    source: Optional[str] = None
    sink: Optional[str] = None
    guard_analysis: Optional[str] = None
    exploit_scenario: Optional[str] = None
    positive_evidence: Optional[List[str]] = None
    negative_evidence: Optional[List[str]] = None
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


    @classmethod
    def from_dict(cls, data: Dict[str, Any], context_function: str = "unknown", issue_index: int = 1) -> "Issue":
        """Create an Issue from a dictionary, filtering out unknown fields and providing defaults."""
        valid_fields = {f.name for f in fields(cls)}
        
        # Mapping for common LLM field variations
        mapping = {
            "type": "category",
            "vulnerability_type": "subcategory",
            "impact": "impact_level",
            "severity": "impact_level",
            "file": "location" 
        }
        
        filtered_data = {}
        for k, v in data.items():
            if k in valid_fields:
                filtered_data[k] = v
            if k in mapping and mapping[k] in valid_fields and mapping[k] not in filtered_data:
                # If we have a mapping and the target field isn't already filled
                filtered_data[mapping[k]] = v
        
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
            "impact_level": "medium"
        }
        
        for field_name, default_val in defaults.items():
            if field_name not in filtered_data or filtered_data[field_name] is None:
                filtered_data[field_name] = default_val
            elif field_name in ["id", "function", "location", "category", "subcategory", "description", "root_cause", "suggested_fix", "impact_level"]:
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
        return asdict(self)


@dataclass
class FinalReport:
    """Represents the final analysis report."""

    entry_function: str
    overall_verdict: str  # no_issue_found, issues_found, insufficient_info
    issues: List[Issue] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    report_views: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_function": self.entry_function,
            "overall_verdict": self.overall_verdict,
            "issues": [issue.to_dict() for issue in self.issues],
            "notes": self.notes,
            "metadata": self.metadata,
            "report_views": self.report_views,
        }


class ReportGenerator:
    """Generates reports in various formats."""

    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)

    @staticmethod
    def _normalize_md_text(value: Optional[str]) -> str:
        if value is None:
            return ""
        return str(value).replace("\\n", "\n")

    def save_json_report(self, report: FinalReport, filename: str = "report.json") -> Path:
        """Save report as JSON."""
        output_path = self.project_root / filename
        data = report.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return output_path

    def save_markdown_report(self, report: FinalReport) -> Path:
        """保存中文分析结论报告。"""
        md_content = f"""# Z-SCOPE 分析报告

**分析时间**: {report.metadata.get('timestamp', '未记录')}
**入口函数**: `{report.entry_function}`
**整体结论**: {self._translate_verdict(report.overall_verdict)}

## 缺陷摘要统计

"""
        if not report.issues:
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
                icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵"
                }.get(issue.impact_level.lower(), "⚪")
                
                md_content += f"### {icon} [{issue.id}] {issue.category}: {issue.subcategory}\n"
                md_content += f"- **所在函数**: `{issue.function}`\n"
                md_content += f"- **代码位置**: `{issue.location}`\n"
                md_content += f"- **置信度**: {issue.confidence:.0%}\n"
                if issue.final_score is not None:
                    md_content += f"- **综合评分**: {issue.final_score:.0%}\n"
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
            "insufficient_info": "🟡 信息不足，无法下定论"
        }
        return translations.get(verdict, verdict)
