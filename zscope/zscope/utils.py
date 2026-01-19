"""
Utility functions for Z-SCOPE.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Optional


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def compute_code_hash(code: str) -> str:
    """Compute SHA256 hash of code content."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def compute_semantic_fingerprint(code: str) -> str:
    """
    Compute a semantic fingerprint by removing comments and normalizing whitespace.
    This helps detect semantic changes vs cosmetic changes.
    """
    # Remove single-line comments
    code = re.sub(r"//.*$", "", code, flags=re.MULTILINE)
    # Remove multi-line comments
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    # Normalize whitespace
    code = re.sub(r"\s+", " ", code)
    code = code.strip()
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def normalize_path(path: str, project_root: Optional[Path] = None) -> str:
    """
    Normalize a file path.
    If project_root is provided, return relative path; otherwise absolute.
    """
    p = Path(path).resolve()
    if project_root:
        try:
            return str(p.relative_to(project_root))
        except ValueError:
            return str(p)
    return str(p)


def extract_function_calls(code: str) -> list[str]:
    """
    Simple heuristic to extract function calls from C code.
    Returns list of function names that appear to be called.
    This is a best-effort approach without full parsing.
    """
    # Match function calls: word followed by (
    pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\("
    matches = re.findall(pattern, code)
    
    # Filter out common keywords that aren't function calls
    keywords = {
        "if", "while", "for", "switch", "return", "sizeof", "typeof",
        "static_assert", "alignof", "_Generic", "offsetof"
    }
    
    return [m for m in matches if m not in keywords]


def truncate_string(s: str, max_length: int = 1000, ellipsis: str = "...") -> str:
    """Truncate string to max_length if needed."""
    if len(s) <= max_length:
        return s
    return s[: max_length - len(ellipsis)] + ellipsis


def validate_json_schema(data: dict, required_fields: list[str]) -> bool:
    """Validate that a dictionary contains all required fields."""
    return all(field in data for field in required_fields)
