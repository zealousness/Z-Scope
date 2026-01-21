"""
Report generation for Z-SCOPE.
Handles conversion of analysis results to JSON and Markdown formats.
"""

import json
from dataclasses import dataclass, asdict, field
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_function": self.entry_function,
            "overall_verdict": self.overall_verdict,
            "issues": [issue.to_dict() for issue in self.issues],
            "notes": self.notes,
            "metadata": self.metadata,
        }


class ReportGenerator:
    """Generates reports in various formats."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_json_report(self, report: FinalReport, filename: str = "report.json") -> Path:
        """Save report as JSON."""
        output_path = self.output_dir / filename
        data = report.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return output_path

    def save_markdown_report(self, report: FinalReport, filename: str = "report.md") -> Path:
        """Save report as Markdown."""
        output_path = self.output_dir / filename
        content = self._generate_markdown(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path

    def _generate_markdown(self, report: FinalReport) -> str:
        """Generate Markdown content from report."""
        lines = []
        lines.append(f"# Z-SCOPE Analysis Report")
        lines.append(f"**Entry Function**: `{report.entry_function}`")
        lines.append(f"**Overall Verdict**: {self._format_verdict(report.overall_verdict)}")
        
        if report.metadata:
            lines.append(f"**Analyzed at**: {report.metadata.get('timestamp', 'N/A')}")
            lines.append(f"**Tool Version**: {report.metadata.get('version', 'N/A')}")

        lines.append("\n## Executive Summary")
        if not report.issues:
            lines.append("No issues were found during the analysis.")
        else:
            critical_count = sum(1 for i in report.issues if i.impact_level == "critical")
            high_count = sum(1 for i in report.issues if i.impact_level == "high")
            medium_count = sum(1 for i in report.issues if i.impact_level == "medium")
            low_count = sum(1 for i in report.issues if i.impact_level == "low")
            
            lines.append("| Impact Level | Count |")
            lines.append("| :--- | :--- |")
            lines.append(f"| 🔴 Critical | {critical_count} |")
            lines.append(f"| 🟠 High | {high_count} |")
            lines.append(f"| 🟡 Medium | {medium_count} |")
            lines.append(f"| 🔵 Low | {low_count} |")

        if report.issues:
            lines.append("\n## Detected Issues")
            for issue in report.issues:
                icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵"
                }.get(issue.impact_level.lower(), "⚪")
                
                lines.append(f"\n### {icon} [{issue.id}] {issue.category}: {issue.subcategory}")
                lines.append(f"- **Function**: `{issue.function}`")
                lines.append(f"- **Location**: `{issue.location}`")
                lines.append(f"- **Confidence**: {issue.confidence:.0%}")
                lines.append(f"\n**Description**:\n{issue.description}")
                lines.append(f"\n**Root Cause**:\n{issue.root_cause}")
                lines.append(f"\n**Suggested Fix**:\n> {issue.suggested_fix}")
                lines.append("\n---")

        if report.notes:
            lines.append("\n## Analysis Notes")
            for note in report.notes:
                lines.append(f"- {note}")

        return "\n".join(lines)

    def _format_verdict(self, verdict: str) -> str:
        if verdict == "no_issue_found":
            return "✅ No Issues Found"
        elif verdict == "issues_found":
            return "⚠️ Issues Found"
        elif verdict == "insufficient_info":
            return "❓ Insufficient Information"
        return verdict
