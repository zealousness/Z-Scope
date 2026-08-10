"""
Function entry configuration for batch analysis.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FunctionEntry:
    """
    Single function entry for batch analysis.

    Attributes:
        function_name: Name of the function to analyze
        custom_prompt: Optional custom prompt to append to agent's base task
        file_path: Optional file path for disambiguation when multiple TUs have same function name
        signature: Complete source signature used to distinguish overloads and
            same-name declarations within one translation unit
        diff_focus: Optional diff-impact metadata used by diff mode
    """

    function_name: str
    custom_prompt: Optional[str] = None
    file_path: Optional[str] = None
    signature: Optional[str] = None
    diff_focus: Optional[Dict[str, Any]] = None
    exposure: Optional[str] = None
    reasons: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.function_name = str(self.function_name).strip()
        if not self.function_name:
            raise ValueError("function_name cannot be empty")
        if self.file_path:
            self.file_path = self._portable_path_text(self.file_path)
        if self.signature:
            self.signature = self.normalize_signature(self.signature)

    @staticmethod
    def _portable_path_text(value: Any) -> str:
        text = str(value or "").strip().replace("\\", "/")
        text = re.sub(r"/+", "/", text)
        while text.startswith("./"):
            text = text[2:]
        return text

    @staticmethod
    def normalize_signature(value: Any) -> str:
        """Return a stable, lossless-enough representation of a declaration."""
        return re.sub(r"\s+", " ", str(value or "").strip())

    def normalized_file_path(self, project_root: Optional[Path] = None) -> str:
        """Return a project-relative POSIX path when a project root is known."""
        text = self._portable_path_text(self.file_path)
        if not text:
            return ""
        if project_root is None:
            return text

        root = Path(project_root).resolve()
        path = Path(text)
        if not path.is_absolute():
            path = root.joinpath(*text.split("/"))
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path.absolute()
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError:
            return resolved.as_posix()

    def identity_key(self, project_root: Optional[Path] = None) -> str:
        """Return the canonical entry identity.

        New entries use implementation file plus a complete callable
        identity. Some frontends (notably Java) store a return-and-parameter
        descriptor that omits the qualified method name, so retain the name
        alongside such a descriptor. The name-only form is retained for one
        compatibility cycle when legacy entry lists do not yet carry either
        field.
        """
        file_path = self.normalized_file_path(project_root)
        signature = self.normalize_signature(self.signature)
        if not file_path and not signature:
            return self.function_name
        callable_identity = signature or self.function_name
        if signature and self.function_name not in signature:
            callable_identity = f"{self.function_name}::{signature}"
        return f"{file_path or '<unknown>'}::{callable_identity}"

    def lookup_query(self) -> str:
        """Prefer the complete signature for overload-safe index lookup."""
        return self.normalize_signature(self.signature) or self.function_name


class FunctionListLoader:
    """Load and validate function list from JSON file."""

    @staticmethod
    def _is_diff_mode_value(value: Any) -> bool:
        return str(value or "").strip().lower() in {
            "diff",
            "diff-impact",
            "diff_impact",
        }

    @classmethod
    def _is_diff_impact_payload(
        cls,
        data: Dict[str, Any],
        *,
        require_declared_mode: bool = False,
    ) -> bool:
        diff_impact = data.get("diff_impact") if isinstance(data.get("diff_impact"), dict) else {}
        declared = any(
            cls._is_diff_mode_value(value)
            for value in (
                data.get("mode"),
                data.get("entry_mode"),
                data.get("analysis_mode"),
                diff_impact.get("mode") if isinstance(diff_impact, dict) else None,
                diff_impact.get("entry_mode") if isinstance(diff_impact, dict) else None,
            )
        )
        if declared:
            return True
        if require_declared_mode:
            return False
        return isinstance(diff_impact, dict) and bool(diff_impact)

    @classmethod
    def is_diff_impact_file(
        cls,
        json_path: Path,
        *,
        require_declared_mode: bool = False,
    ) -> bool:
        """Return true when a function-list JSON carries diff-impact metadata."""
        json_path = Path(json_path)
        if not json_path.exists() or not json_path.is_file():
            return False
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(data, dict):
            return False
        return cls._is_diff_impact_payload(
            data,
            require_declared_mode=require_declared_mode,
        )

    @staticmethod
    def _normalize_diff_focus(
        raw_focus: Any,
        diff_impact: Dict[str, Any],
        *,
        is_diff_impact: bool,
        function_name: str,
        file_path: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        if isinstance(raw_focus, dict):
            focus: Dict[str, Any] = dict(raw_focus)
        elif is_diff_impact:
            focus = {}
        else:
            return None

        if not is_diff_impact:
            return focus

        focus.setdefault("mode", "diff_impact")
        for key in (
            "component",
            "repo_root",
            "git_root",
            "source_root",
            "project_root",
            "requested_repo_root",
            "base_ref",
            "head_ref",
            "path_filters",
        ):
            if key not in focus and key in diff_impact:
                focus[key] = diff_impact[key]
        if function_name:
            focus.setdefault("entry_function", function_name)
        if file_path:
            focus.setdefault("entry_file_path", file_path)
        if "changed_functions" not in focus and isinstance(
            diff_impact.get("changed_functions"),
            list,
        ):
            focus["changed_functions"] = list(diff_impact.get("changed_functions") or [])
        focus.setdefault("affected_paths", [])
        focus.setdefault("fallback_reasons", [])
        return focus

    @staticmethod
    def load(json_path: Path) -> List[FunctionEntry]:
        """
        Load function entries from JSON file.

        Args:
            json_path: Path to JSON file containing function entries

        Returns:
            List of FunctionEntry objects

        Raises:
            FileNotFoundError: If JSON file doesn't exist
            ValueError: If JSON format is invalid
        """
        json_path = Path(json_path)
        if not json_path.exists():
            raise FileNotFoundError(f"Function list file not found: {json_path}")

        try:
            raw_json = json_path.read_text(encoding="utf-8")
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Invalid JSON in %s. Raw content:\n%s",
                    json_path,
                    raw_json,
                )
            raise ValueError(f"Invalid JSON in {json_path}: {e}")

        if not isinstance(data, dict):
            raise ValueError(f"JSON root must be an object, got {type(data).__name__}")

        diff_impact = data.get("diff_impact") if isinstance(data.get("diff_impact"), dict) else {}
        is_diff_impact = FunctionListLoader._is_diff_impact_payload(data)

        if "functions" not in data:
            raise ValueError("JSON must contain 'functions' array")

        functions_data = data["functions"]
        if not isinstance(functions_data, list):
            raise ValueError(f"'functions' must be an array, got {type(functions_data).__name__}")

        entries = []
        for idx, func_data in enumerate(functions_data):
            if not isinstance(func_data, dict):
                logger.warning(f"Skipping invalid entry at index {idx}: not an object")
                continue

            try:
                function_name = func_data.get("function_name", "")
                file_path = func_data.get("file_path")
                diff_focus = FunctionListLoader._normalize_diff_focus(
                    func_data.get("diff_focus"),
                    diff_impact,
                    is_diff_impact=is_diff_impact,
                    function_name=str(function_name or ""),
                    file_path=file_path,
                )
                reasons_source = func_data.get("reasons")
                if reasons_source is None and isinstance(diff_focus, dict):
                    reasons_source = diff_focus.get("entry_reasons")
                exposure = func_data.get("exposure")
                if exposure is None and isinstance(diff_focus, dict):
                    exposure = diff_focus.get("entry_exposure")

                entry = FunctionEntry(
                    function_name=function_name,
                    custom_prompt=func_data.get("custom_prompt"),
                    file_path=file_path,
                    signature=func_data.get("signature"),
                    diff_focus=diff_focus,
                    exposure=exposure,
                    reasons=[
                        str(reason) for reason in (reasons_source or []) if str(reason).strip()
                    ],
                )
                entries.append(entry)
                logger.debug(f"Loaded function entry: {entry.function_name}")
            except ValueError as e:
                logger.warning(f"Skipping invalid entry at index {idx}: {e}")
                continue

        if not entries:
            raise ValueError("No valid function entries found in JSON file")

        logger.info(f"Loaded {len(entries)} function entries from {json_path}")
        return entries
