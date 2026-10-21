"""Fail-closed deterministic Markdown classification."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .models import ClassificationResult, DiscoveredFile

_yaml: Any
try:
    import yaml as _yaml
except ImportError:  # pragma: no cover
    _yaml = None

yaml: Any = _yaml


RUNTIME_NAMES = frozenset({"agents.md", "claude.md", "gemini.md", "skill.md"})
TRUTH_NAMES = frozenset({"ground_truth.md", "ground-truth.md", "answer.md", "answers.md"})
_SECRET_PATTERNS = (
    re.compile(r"(?im)^\s*authorization\s*:\s*(?:bearer|basic)\s+\S+"),
    re.compile(r"(?i)private[_ -]?endpoint|private response|fixture-token|api[_ -]?key\s*[:=]"),
    re.compile(r"(?i)chain[- ]of[- ]thought|raw reasoning|internal reasoning"),
)
_NORMATIVE_HINT = re.compile(r"(?i)\b(must|shall|required|only|range|contract|accepts?|returns?|error|ownership|lock)\b")


def _frontmatter_block(text: str) -> Optional[str]:
    if not text.startswith("---"):
        return None
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    end = next((i for i in range(1, len(lines)) if lines[i].strip() in {"---", "..."}), None)
    if end is None:
        return "__MALFORMED__"
    return "\n".join(lines[1:end]).strip()


if yaml is not None:  # pragma: no branch - exercised when PyYAML is installed.
    class _UniqueLoader(yaml.SafeLoader):
        pass

    def _construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> Dict[Any, Any]:
        mapping: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError(f"duplicate frontmatter key: {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    _UniqueLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_unique_mapping,
    )


def frontmatter_info(text: str) -> Tuple[bool, bool, Dict[str, Any]]:
    """Return ``(present, valid, mapping)`` for a leading metadata block."""

    raw = _frontmatter_block(text)
    if raw is None:
        return False, True, {}
    if raw == "__MALFORMED__" or yaml is None:
        return True, False, {}
    if not raw:
        return True, True, {}
    try:
        value = yaml.load(raw, Loader=_UniqueLoader)
    except Exception:
        return True, False, {}
    return True, isinstance(value, dict), value if isinstance(value, dict) else {}


def parse_frontmatter(text: str) -> Dict[str, Any]:
    """Parse only a leading YAML frontmatter block; malformed metadata is {}."""

    return frontmatter_info(text)[2]


def validate_overrides(overrides: Optional[Mapping[str, Any]]) -> Dict[str, Tuple[Tuple[str, str], ...]]:
    """Normalize project-relative override globs and reject unsafe conflicts."""

    if not overrides:
        return {"exclude": (), "explanatory": (), "generated": ()}
    result: Dict[str, Tuple[Tuple[str, str], ...]] = {
        "exclude": (),
        "explanatory": (),
        "generated": (),
    }
    for kind in ("exclude", "explanatory", "generated"):
        values = overrides.get(kind, ())
        if isinstance(values, str):
            values = (values,)
        pairs = []
        for index, value in enumerate(values or ()):
            pattern = str(value).replace("\\", "/")
            if pattern.startswith("/") or ".." in PurePosixPath(pattern).parts:
                raise ValueError(f"unsafe wiki classification glob: {pattern!r}")
            pairs.append((f"{kind}:{index}", pattern))
        result[kind] = tuple(pairs)
    for left_id, left in result["explanatory"]:
        for right_id, right in result["generated"]:
            if left == right:
                raise ValueError(f"classification override conflict: {left!r}")
    return result


def _matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern) or PurePosixPath(path).match(pattern)


def _mandatory(relative: str) -> Optional[Tuple[str, str]]:
    path = PurePosixPath(relative)
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    if name in RUNTIME_NAMES or name == "agent.md" or ("zscope" in parts and "agents" in parts and name.endswith(".md")):
        return "runtime_instruction", "mandatory_runtime_instruction"
    if name in TRUTH_NAMES or "ground_truth" in {part.lower() for part in path.parts} or "truth" in parts or any(token in name for token in ("benchmark-answer", "ablation-truth")):
        return "benchmark_truth", "mandatory_benchmark_truth"
    if ".zscope_knowledge" in parts or ".zscope_snapshots" in parts:
        return "generated_artifact", "mandatory_generated_state"
    lower = relative.lower()
    if any(token in lower for token in ("/model_trace", "/model-trace", "/conversation", "/scan-report", "/batch-report", "/sarif-report")):
        return "generated_artifact", "mandatory_generated_output"
    return None


def classify_document(
    document: DiscoveredFile,
    *,
    overrides: Optional[Mapping[str, Any]] = None,
) -> ClassificationResult:
    """Classify a discovered Markdown document using ordered deterministic rules."""

    relative = document.relative_path.replace("\\", "/")
    normalized = validate_overrides(overrides)
    mandatory = _mandatory(relative)
    if mandatory:
        return ClassificationResult(relative, mandatory[0], mandatory[1], (mandatory[1],), document.content_digest)

    present, valid, metadata = frontmatter_info(document.text)
    if present and not valid:
        return ClassificationResult(relative, "unknown", "invalid_frontmatter", ("frontmatter:invalid",), document.content_digest)
    for marker in ("generated_by", "artifact_kind", "source_manifest_digest", "producer", "do_not_edit"):
        if marker in metadata:
            return ClassificationResult(relative, "generated_artifact", f"generated_frontmatter_{marker}", (f"frontmatter:{marker}",), document.content_digest)
    for secret_pattern in _SECRET_PATTERNS:
        if secret_pattern.search(document.text):
            return ClassificationResult(relative, "sensitive_rejected", "sensitive_content_marker", ("sensitive:content_marker",), document.content_digest)

    # Public exclusions are fail-closed corpus filters.  They cannot weaken a
    # mandatory, generated-provenance, or sensitive classification, but they
    # must be able to exclude otherwise explanatory README/docs content.
    for override_id, pattern in normalized["exclude"]:
        if _matches(relative, pattern):
            return ClassificationResult(
                relative,
                "unknown",
                "user_excluded_path",
                (f"override:{override_id}",),
                document.content_digest,
                override_id,
            )

    contract = metadata.get("zscope_document")
    if isinstance(contract, Mapping):
        kind = contract.get("kind")
        if kind == "explanatory":
            return ClassificationResult(relative, "explanatory", "explicit_document_contract", ("frontmatter:zscope_document.explanatory",), document.content_digest)
        if kind == "generated":
            return ClassificationResult(relative, "generated_artifact", "explicit_document_contract_generated", ("frontmatter:zscope_document.generated",), document.content_digest)
        if kind is not None:
            return ClassificationResult(relative, "unknown", "invalid_document_contract", ("frontmatter:zscope_document.invalid",), document.content_digest)

    name = PurePosixPath(relative).name
    lower = relative.lower()
    if name.lower() == "readme.md" and "/" not in relative:
        return ClassificationResult(relative, "explanatory", "explicit_project_readme", ("path:project_readme",), document.content_digest)
    if lower.startswith("docs/") or "/docs/" in lower or name.lower() in {"architecture.md", "api.md", "protocol.md", "design.md"}:
        return ClassificationResult(relative, "explanatory", "explanatory_path_contract", ("path:documentation",), document.content_digest)
    path_parts = {part.lower() for part in PurePosixPath(relative).parts}
    if any(token in path_parts for token in {"report", "reports", "logs", "output", "outputs", "coverage", "profiles", "traces", "conversations"}) or any(token in lower for token in ("/report-", ".report.", "/scan-report", "/batch-report")):
        return ClassificationResult(relative, "generated_artifact", "generated_path_contract", ("path:generated_output",), document.content_digest)
    if _NORMATIVE_HINT.search(document.text):
        return ClassificationResult(relative, "explanatory", "content_explanatory_threshold", ("content:normative_terms",), document.content_digest)
    for override_id, pattern in normalized["explanatory"]:
        if _matches(relative, pattern):
            return ClassificationResult(relative, "explanatory", "explanatory_override", (f"override:{override_id}",), document.content_digest, override_id)
    for override_id, pattern in normalized["generated"]:
        if _matches(relative, pattern):
            return ClassificationResult(relative, "generated_artifact", "generated_override", (f"override:{override_id}",), document.content_digest, override_id)
    return ClassificationResult(relative, "unknown", "insufficient_classification_evidence", ("fallback:unknown",), document.content_digest)


class DocumentClassifier:
    def __init__(self, overrides: Optional[Mapping[str, Any]] = None):
        self.overrides = dict(overrides or {})

    def classify(self, document: DiscoveredFile) -> ClassificationResult:
        return classify_document(document, overrides=self.overrides)

    classify_file = classify


classify_file = classify_document


def override_digest(overrides: Optional[Mapping[str, Any]]) -> Optional[str]:
    normalized = validate_overrides(overrides)
    if not any(normalized.values()):
        return None
    payload = {key: [pattern for _, pattern in value] for key, value in sorted(normalized.items())}
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


__all__ = ["DocumentClassifier", "classify_document", "parse_frontmatter", "frontmatter_info", "validate_overrides", "override_digest"]
