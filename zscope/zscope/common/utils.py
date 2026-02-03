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
    code = _strip_c_comments_preserve_strings(code)
    code = re.sub(r"\s+", " ", code).strip()
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _strip_c_comments_preserve_strings(code: str) -> str:
    """Remove C-style comments while preserving strings and char literals."""
    result = []
    i = 0
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False

    while i < len(code):
        ch = code[i]
        nxt = code[i + 1] if i + 1 < len(code) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                result.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        if in_string:
            result.append(ch)
            if ch == "\\" and nxt:
                result.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue

        if in_char:
            result.append(ch)
            if ch == "\\" and nxt:
                result.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_char = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == "'":
            in_char = True
            result.append(ch)
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


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


def is_valid_snapshot(d: dict) -> bool:
    """Check if dictionary looks like a function snapshot."""
    snapshot_keys = {"type", "func_name", "summary", "key_semantics", "inputs"}
    return isinstance(d, dict) and (
        d.get("type") == "function_snapshot" or 
        any(k in d for k in snapshot_keys)
    )


def is_valid_report(d: dict) -> bool:
    """Check if dictionary looks like a final report."""
    return isinstance(d, dict) and (
        d.get("type") == "final_report" or 
        "issues" in d or 
        "overall_verdict" in d
    )


def extract_json_blocks(text: str) -> list[dict]:
    """
    Extract all valid JSON objects from text.
    Handles nested structures, markdown blocks, and partial truncation.
    """
    import json
    results = []
    
    # Strategy 1: Find all markdown code blocks (greedy)
    md_blocks = re.findall(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    # Also try even more greedy version if that misses
    md_blocks += re.findall(r"```(?:json)?\n?(\{[\s\S]*\})\n?```", text)
    
    for block in md_blocks:
        try:
            data = json.loads(block)
            if isinstance(data, dict) and data not in results:
                results.append(data)
        except:
            # Try to fix partial truncation at the end of a block
            for k in range(len(block)-1, 0, -1):
                if block[k] == '}':
                    try:
                        data = json.loads(block[:k+1])
                        if isinstance(data, dict) and data not in results:
                            results.append(data)
                        break
                    except:
                        continue

    # Strategy 2: Find the largest balanced { ... } blocks
    # This is more robust for raw text with JSON
    for i in range(len(text)):
        if text[i] == '{':
            # Try from end of string to find the matching }
            for j in range(len(text) - 1, i, -1):
                if text[j] == '}':
                    candidate = text[i : j + 1]
                    try:
                        data = json.loads(candidate)
                        if isinstance(data, dict) and data not in results:
                            results.append(data)
                        break # Found the largest possible object starting at i
                    except:
                        continue
                        
    # Strategy 3: Aggressive recovery for truncated JSON
    # If no results yet, or we want to be safe, try fixing text that starts with { but never ends
    if not results:
        for i in range(len(text)):
            if text[i] == '{':
                candidate = text[i:]
                # Try adding 1 to 5 closing braces at the very end of the string
                for k in range(1, 6):
                    try:
                        data = json.loads(candidate + "}" * k)
                        if isinstance(data, dict):
                            results.append(data)
                            return results # Found one, good enough
                    except:
                        continue
                # Also try adding } after the last meaningful character if there is trailing noise
                # But the above loop usually covers it if we trim the candidate first
                trimmed = candidate.strip()
                for k in range(1, 6):
                    try:
                        data = json.loads(trimmed + "}" * k)
                        if isinstance(data, dict):
                            results.append(data)
                            return results
                    except:
                        continue
    
    return results
