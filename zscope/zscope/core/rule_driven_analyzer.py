"""
Rule-driven analyzer for Z-SCOPE.
Runs Joern rules, then validates findings with LLM ValidatorAgent.
"""

import json
import logging
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..retrieval.code_index import CodeIndex
from .rule_engine import RuleEngine, RuleMatch
from .report import FinalReport, Issue, ReportGenerator
from ..framework.llm_client import LLMClient

logger = logging.getLogger(__name__)


class RuleDrivenAnalyzer:
    """Runs Joern rules then validates with LLM agent."""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: CodeIndex,
        user_config: Optional[UserConfigStore] = None,
    ):
        self.config = config
        self.code_index = code_index
        db_dir = (
            Path(config.analysis.user_config_db)
            if config.analysis.user_config_db
            else Path(config.analysis.snapshot_dir)
        )
        self.user_config = user_config or UserConfigStore(db_dir)
        self.llm_client = LLMClient(
            api_key=config.llm.api_key,
            base_url=config.llm.base_url,
            models=config.llm.models,
            timeout=config.llm.timeout,
            max_retries=config.llm.max_retries,
            max_tokens=config.llm.max_tokens,
        )
        self.report_generator = ReportGenerator(config.project.project_root)

        if not code_index.joern_client:
            raise ValueError("Rule-driven mode requires Joern CPG backend")
        self.rule_engine = RuleEngine(code_index.joern_client, self.user_config)

    def run(self, custom_script_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute rule-driven analysis pipeline."""
        logger.info("Starting rule-driven analysis")
        all_matches: List[RuleMatch] = []

        # 1. Joern built-in scan
        logger.info("Running Joern built-in scan...")
        all_matches.extend(self.rule_engine.run_builtin_scan())

        # 2. Paired function checks
        logger.info("Running paired function checks...")
        all_matches.extend(self.rule_engine.run_paired_function_checks())

        # 3. Custom scripts
        if custom_script_dir and Path(custom_script_dir).is_dir():
            logger.info("Running custom scripts from %s", custom_script_dir)
            all_matches.extend(self.rule_engine.run_custom_scripts(custom_script_dir))

        logger.info("Total rule matches: %d", len(all_matches))
        if not all_matches:
            return self._build_report([], [])

        # 4. Group by function and validate
        by_func: Dict[str, List[RuleMatch]] = {}
        for m in all_matches:
            by_func.setdefault(m.func_name, []).append(m)

        validated_issues: List[Dict[str, Any]] = []
        notes: List[str] = []

        validator_enabled = any(
            a.name == "validator_agent" and a.enabled
            for a in self.config.project.agents
        )

        for func_name, matches in by_func.items():
            issues_for_func = [m.to_dict() for m in matches]

            if validator_enabled:
                issues_for_func = self._validate_matches(func_name, issues_for_func)

            validated_issues.extend(issues_for_func)
            notes.append(f"Checked {func_name}: {len(matches)} rule matches")

        # 5. Filter false positives
        validated_issues = self._filter_false_positives(validated_issues)

        return self._build_report(validated_issues, notes)

    def _validate_matches(
        self, func_name: str, issues: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Validate rule matches using ValidatorAgent."""
        from ..agents.validator_agent.agent import ValidatorAgent
        from ..tools.code_retrieval import GetFunctionImplTool
        from ..tools.snapshot_tool import GetFunctionSnapshotTool
        from .snapshot_store import SnapshotStore

        tools = [
            GetFunctionImplTool(self.code_index),
            GetFunctionSnapshotTool(
                SnapshotStore(Path(self.config.analysis.snapshot_dir))
            ),
        ]
        validator = ValidatorAgent(self.llm_client, tools)

        impl = self.code_index.get_function_impl(func_name)
        context_code = impl["code"] if impl else ""

        validated = []
        for issue in issues:
            val_input = {
                "finding": json.dumps(issue, indent=2, ensure_ascii=False),
                "context_code": context_code,
            }
            resp = validator.run(val_input)
            if resp.success:
                data = resp.data
                issue["validation_status"] = (
                    "validated" if data.get("is_valid") else "rejected"
                )
                issue["validation_reasoning"] = data.get("reasoning")
                issue["confidence"] = data.get(
                    "confidence_score", issue.get("confidence", 0.5)
                )
            else:
                logger.warning(
                    "Validation failed for rule %s in %s: %s",
                    issue.get("rule_id"), func_name, resp.error,
                )
                issue["validation_status"] = "pending"
                issue["validation_error"] = resp.error
            validated.append(issue)
        return validated

    def _filter_false_positives(
        self, issues: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        filtered = []
        for issue in issues:
            func = issue.get("function", "")
            loc = f"{issue.get('file_path', '')}:{issue.get('line_number', '')}"
            subcat = issue.get("category", "")
            if self.user_config.is_false_positive(func, loc, subcat):
                logger.info("Filtering false positive: %s in %s", issue.get("rule_id"), func)
                continue
            filtered.append(issue)
        return filtered

    def _build_report(
        self, issues: List[Dict[str, Any]], notes: List[str]
    ) -> Dict[str, Any]:
        verdict = "issues_found" if issues else "no_issue_found"
        report = FinalReport(
            entry_function="[rule-driven]",
            overall_verdict=verdict,
            issues=[
                Issue.from_dict(i, context_function=i.get("function", ""), issue_index=idx + 1)
                for idx, i in enumerate(issues)
                if isinstance(i, dict)
            ],
            notes=notes,
        )
        report.metadata = {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "0.1.0",
            "mode": "rule_driven",
        }
        self.report_generator.save_json_report(report)
        self.report_generator.save_markdown_report(report)
        return report.to_dict()
