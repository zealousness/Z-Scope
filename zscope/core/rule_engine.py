"""
Rule engine for Z-SCOPE rule-driven analysis mode.
Executes Joern built-in/community rules and custom paired-function checks.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..common.joern_client import JoernClient
from ..config.user_config_store import UserConfigStore

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    category: str
    score: float
    func_name: str
    file_path: str
    line_number: int
    code_snippet: str = ""
    evidence: List[dict] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "score": self.score,
            "function": self.func_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "evidence": self.evidence,
        }


class RuleEngine:
    """Executes Joern rules and custom checks, returns RuleMatch list."""

    def __init__(self, joern_client: JoernClient, user_config: Optional[UserConfigStore] = None):
        self.joern = joern_client
        self.user_config = user_config

    def run_builtin_scan(self) -> List[RuleMatch]:
        """Run Joern built-in scan rules via run.scan."""
        result = self.joern.query("run.scan.toJson")
        return self._parse_scan_result(result)

    def run_custom_scripts(self, script_dir: str) -> List[RuleMatch]:
        """Run .sc scripts from a directory."""
        matches = []
        scripts = sorted(Path(script_dir).glob("*.sc"))
        for script in scripts:
            try:
                proc = subprocess.run(
                    [self.joern.joern_path, "--script", str(script)],
                    capture_output=True, text=True, timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    try:
                        data = json.loads(proc.stdout)
                        matches.extend(self._parse_script_output(data, script.stem))
                    except json.JSONDecodeError:
                        logger.debug("Non-JSON output from %s", script.name)
            except Exception as e:
                logger.error("Script %s failed: %s", script.name, e)
        return matches

    def run_paired_function_checks(self) -> List[RuleMatch]:
        """Check paired functions (e.g. malloc/free) using CPGQL."""
        if not self.user_config:
            return []
        pairs = self.user_config.list_paired_functions()
        matches = []
        for pair in pairs:
            acq = pair["acquire_func"]
            rel = pair["release_func"]
            cat = pair.get("category", "resource")
            new_matches = self._check_one_pair(acq, rel, cat)
            matches.extend(new_matches)
        return matches

    def _check_one_pair(self, acquire: str, release: str, category: str) -> List[RuleMatch]:
        """Check that every call to acquire has a matching release in the same function."""
        query = (
            f'cpg.method.filter(m => m.callee.name("{acquire}").nonEmpty '
            f'&& m.callee.name("{release}").isEmpty)'
            f'.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1))).l.toJson'
        )
        result = self.joern.query(query)
        if not isinstance(result, list):
            return []
        matches = []
        for item in result:
            name = item.get("name", "")
            if not name or name.startswith("<"):
                continue
            line_value = item.get("lineNumber", -1)
            matches.append(RuleMatch(
                rule_id=f"paired_{acquire}_{release}",
                rule_name=f"Missing {release} for {acquire}",
                category=category,
                score=6.0,
                func_name=name,
                file_path=str(item.get("filename", "")),
                line_number=int(line_value if line_value is not None else -1),
            ))
        return matches

    def _parse_scan_result(self, result: Any) -> List[RuleMatch]:
        """Parse Joern run.scan JSON output."""
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                return []
        if not isinstance(result, list):
            return []
        matches = []
        for item in result:
            line_value = item.get("lineNumber", -1)
            matches.append(RuleMatch(
                rule_id=str(item.get("name", "unknown")),
                rule_name=str(item.get("title", item.get("name", ""))),
                category=str(item.get("tags", ["unknown"])[0] if item.get("tags") else "unknown"),
                score=float(item.get("score", 5.0)),
                func_name=str(item.get("methodFullName", item.get("methodName", ""))),
                file_path=str(item.get("filename", "")),
                line_number=int(line_value if line_value is not None else -1),
                code_snippet=str(item.get("code", "")),
                evidence=item.get("evidence", []),
            ))
        return matches

    def _parse_script_output(self, data: Any, script_name: str) -> List[RuleMatch]:
        """Parse custom script JSON output into RuleMatch list."""
        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []
        matches = []
        for item in data:
            if not isinstance(item, dict):
                continue
            line_value = item.get("line_number", item.get("lineNumber", -1))
            matches.append(RuleMatch(
                rule_id=str(item.get("rule_id", script_name)),
                rule_name=str(item.get("rule_name", script_name)),
                category=str(item.get("category", "custom")),
                score=float(item.get("score", 5.0)),
                func_name=str(item.get("function", item.get("func_name", ""))),
                file_path=str(item.get("file_path", item.get("filename", ""))),
                line_number=int(line_value if line_value is not None else -1),
                code_snippet=str(item.get("code_snippet", item.get("code", ""))),
                evidence=item.get("evidence", []),
            ))
        return matches
