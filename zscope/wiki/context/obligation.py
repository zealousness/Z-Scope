"""Build deterministic document-query obligations from candidate metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple


_FACT_KIND_TERMS = {
    "input_range": ("range", "min", "max", "limit", "bounds", "上限", "下限", "范围"),
    "input_format": ("format", "syntax", "encoding", "格式", "编码"),
    "caller_precondition": ("precondition", "before", "require", "前置", "调用前"),
    "return_contract": ("return", "result", "返回", "结果"),
    "error_contract": ("error", "failure", "status", "错误", "失败"),
    "nullability": ("null", "nullable", "nonnull", "空", "非空"),
    "size_contract": ("size", "length", "capacity", "大小", "长度", "容量"),
    "requires_lock": ("lock", "mutex", "synchronize", "锁", "互斥"),
    "protects_state": ("protect", "guard", "state", "保护", "状态"),
    "lock_order": ("lock order", "ordering", "deadlock", "锁顺序", "死锁"),
    "ownership_acquire": ("acquire", "ownership", "取得", "所有权"),
    "ownership_release": ("release", "free", "destroy", "释放", "销毁"),
    "ownership_transfer": ("transfer", "borrow", "转移", "借用"),
}

# Validator evidence uses ``value_range`` while the Wiki contract calls the
# same obligation ``input_range``.  Keep the source-index query vocabulary
# canonical without requiring callers to know the Wiki-specific spelling.
_OBLIGATION_KIND_ALIASES = {
    "value_range": "input_range",
}


def canonical_obligation_kind(value: str) -> str:
    return _OBLIGATION_KIND_ALIASES.get(str(value or "").strip(), str(value or "").strip())


def _clean_items(values: Any) -> Tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return ()
    result = []
    for value in values:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return tuple(result)


@dataclass(frozen=True)
class ConstraintObligation:
    """Stable, bounded query projection of a Validator candidate."""

    project_id: str = ""
    module_ids: Tuple[str, ...] = ()
    subject_ids: Tuple[str, ...] = ()
    obligation_kind: str = "unknown"
    candidate_file: str = ""
    function_id: Optional[str] = None
    entry_function: Optional[str] = None
    resource_ids: Tuple[str, ...] = ()
    lock_ids: Tuple[str, ...] = ()
    extra_terms: Tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ConstraintObligation":
        target = value.get("target") if isinstance(value.get("target"), Mapping) else value
        project_id = str(value.get("project_id") or target.get("project_id") or "").strip()
        candidate_file = str(
            target.get("candidate_file")
            or target.get("relative_file")
            or target.get("file_path")
            or value.get("candidate_file")
            or value.get("relative_file")
            or ""
        ).replace("\\", "/").lstrip("/")
        raw_kind = str(
            target.get("obligation_kind")
            or target.get("fact_kind")
            or target.get("missing_fact_kind")
            or value.get("obligation_kind")
            or value.get("fact_kind")
            or "unknown"
        ).strip()
        obligation_kind = _OBLIGATION_KIND_ALIASES.get(raw_kind, raw_kind)
        subject_values = target.get("subject_ids")
        if subject_values is None:
            subject_values = (
                target.get("subject_id")
                or target.get("subject_uid")
                or target.get("symbol")
                or target.get("api")
            )
        module_values = target.get("module_ids")
        if module_values is None:
            module_values = target.get("module_id") or target.get("module")
        return cls(
            project_id=project_id,
            module_ids=_clean_items(module_values),
            subject_ids=_clean_items(subject_values),
            obligation_kind=obligation_kind,
            candidate_file=candidate_file,
            function_id=(
                str(target.get("function_id") or target.get("function") or "").strip() or None
            ),
            entry_function=(
                str(target.get("entry_function") or target.get("entry") or "").strip() or None
            ),
            resource_ids=_clean_items(target.get("resource_ids")),
            lock_ids=_clean_items(target.get("lock_ids")),
            extra_terms=_clean_items(target.get("terms") or value.get("terms")),
        )

    def query_terms(self) -> Tuple[str, ...]:
        values = []
        for item in self.subject_ids + (self.function_id or "", self.entry_function or ""):
            if item:
                values.append(item)
                values.append(item.rsplit(":", 1)[-1])
        values.extend(self.resource_ids)
        values.extend(self.lock_ids)
        values.extend(self.extra_terms)
        values.extend(_FACT_KIND_TERMS.get(canonical_obligation_kind(self.obligation_kind), ()))
        result = []
        for value in values:
            text = str(value).strip()
            if text and text.lower() not in {item.lower() for item in result}:
                result.append(text)
        return tuple(result)

    def path_matches(self, relative_path: str) -> bool:
        if not self.candidate_file:
            return False
        candidate = PurePosixPath(self.candidate_file)
        actual = PurePosixPath(relative_path)
        return actual == candidate or candidate in actual.parents
