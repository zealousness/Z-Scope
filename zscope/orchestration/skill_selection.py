"""Select vulnerability-mining skills from a user task."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set


@dataclass
class SkillSelection:
    """Resolved skill subset for one vulnerability analyzer invocation."""

    skills: List[str]
    restricted: bool
    source: str = "local"
    confidence: float = 0.0
    reasons: List[str] = field(default_factory=list)


SemanticSkillRouter = Callable[[str, Sequence[str]], Mapping[str, Any]]


NEGATION_MARKERS = [
    "不关心",
    "不关注",
    "不需要",
    "不要",
    "无需",
    "不用",
    "忽略",
    "排除",
    "not ",
    "no ",
    "ignore ",
    "exclude ",
]


SKILL_KEYWORDS: Dict[str, List[str]] = {
    "resource_lifecycle": [
        "resource_lifecycle",
        "resource lifecycle",
        "resource",
        "资源",
        "泄漏",
        "leak",
        "lifecycle",
        "生命周期",
        "cleanup",
        "清理",
        "release",
        "释放",
        "句柄",
        "handle",
        "socket",
        "file",
    ],
    "bounds_and_integer": [
        "bounds_and_integer",
        "bounds",
        "bound",
        "integer",
        "整数",
        "边界",
        "越界",
        "缓冲区",
        "buffer",
        "overflow",
        "underflow",
        "溢出",
        "oob",
        "拷贝",
        "copy",
        "长度",
        "size",
    ],
    "null_and_failure": [
        "null_and_failure",
        "null",
        "空指针",
        "空引用",
        "failure",
        "失败",
        "错误处理",
        "异常处理",
        "返回值",
        "unchecked",
        "未检查",
    ],
    "temporal_memory": [
        "temporal_memory",
        "temporal",
        "use after free",
        "use-after-free",
        "uaf",
        "double free",
        "invalid free",
        "释放后使用",
        "重复释放",
        "二次释放",
        "悬垂",
        "野指针",
    ],
    "concurrency_lock_order": [
        "concurrency_lock_order",
        "lock order",
        "lock",
        "mutex",
        "deadlock",
        "锁",
        "死锁",
        "锁顺序",
        "锁平衡",
    ],
    "shared_state_race": [
        "shared_state_race",
        "race",
        "data race",
        "shared state",
        "global",
        "竞态",
        "竞争",
        "数据竞争",
        "共享状态",
        "全局状态",
    ],
    "stack_escape": [
        "stack_escape",
        "stack escape",
        "stack address",
        "栈逃逸",
        "栈地址",
        "局部变量地址",
        "异步生命周期",
        "async lifetime",
    ],
    "ownership_contract": [
        "ownership_contract",
        "ownership",
        "contract",
        "caller",
        "callee",
        "所有权",
        "归属",
        "契约",
        "调用方",
        "被调方",
        "逻辑",
        "logic",
    ],
    "string_and_format": [
        "string_and_format",
        "string",
        "format",
        "printf",
        "字符串",
        "格式化",
        "格式串",
        "nul",
        "null termination",
    ],
}


GROUP_KEYWORDS: Dict[str, List[str]] = {
    "内存安全": [
        "resource_lifecycle",
        "bounds_and_integer",
        "null_and_failure",
        "temporal_memory",
        "stack_escape",
        "string_and_format",
    ],
    "memory safety": [
        "resource_lifecycle",
        "bounds_and_integer",
        "null_and_failure",
        "temporal_memory",
        "stack_escape",
        "string_and_format",
    ],
    "并发": ["concurrency_lock_order", "shared_state_race", "stack_escape"],
    "concurrency": ["concurrency_lock_order", "shared_state_race", "stack_escape"],
    "thread": ["concurrency_lock_order", "shared_state_race", "stack_escape"],
    "线程": ["concurrency_lock_order", "shared_state_race", "stack_escape"],
    "可靠性": ["null_and_failure", "resource_lifecycle"],
    "reliability": ["null_and_failure", "resource_lifecycle"],
}


ISSUE_KEYWORDS: Dict[str, List[str]] = {
    "resource_lifecycle": [
        "resource",
        "leak",
        "resource_leak",
        "double_close",
        "资源",
        "泄漏",
        "关闭",
        "cleanup",
        "file",
        "socket",
    ],
    "bounds_and_integer": [
        "bounds",
        "buffer",
        "overflow",
        "underflow",
        "out_of_bounds",
        "oob",
        "integer",
        "truncation",
        "越界",
        "缓冲区",
        "溢出",
        "整数",
        "截断",
        "长度",
    ],
    "null_and_failure": [
        "null",
        "failure",
        "unchecked",
        "空指针",
        "失败",
        "未检查",
        "错误处理",
        "返回值",
    ],
    "temporal_memory": [
        "uaf",
        "use_after_free",
        "use-after-free",
        "double_free",
        "invalid_free",
        "释放后使用",
        "重复释放",
        "二次释放",
        "悬垂",
        "野指针",
    ],
    "concurrency_lock_order": [
        "concurrency",
        "lock",
        "deadlock",
        "mutex",
        "锁",
        "死锁",
        "并发",
    ],
    "shared_state_race": [
        "concurrency",
        "race",
        "shared",
        "global",
        "竞态",
        "竞争",
        "共享",
        "并发",
    ],
    "stack_escape": [
        "stack",
        "escape",
        "async",
        "栈",
        "逃逸",
        "局部变量",
        "异步",
    ],
    "ownership_contract": [
        "ownership",
        "contract",
        "api",
        "logic",
        "所有权",
        "契约",
        "逻辑",
        "生命周期",
    ],
    "string_and_format": [
        "string",
        "format",
        "printf",
        "termination",
        "字符串",
        "格式",
        "终止符",
    ],
}


EXPLICIT_SCOPE_MARKERS = [
    "only",
    "focus",
    "focused",
    "specifically",
    "particular",
    "restrict",
    "limit",
    "just ",
    "只",
    "仅",
    "专门",
    "重点",
    "聚焦",
    "关注",
    "排查",
    "检查",
    "分析",
]


GENERAL_SCOPE_MARKERS = [
    "all",
    "general",
    "overall",
    "comprehensive",
    "full",
    "security audit",
    "all vulnerabilities",
    "全面",
    "所有",
    "全部",
    "整体",
    "通用",
    "安全审计",
]


STRONG_SKILL_KEYWORDS: Dict[str, List[str]] = {
    "resource_lifecycle": [
        "resource leak",
        "memory leak",
        "leak",
        "cleanup",
        "release path",
        "lifecycle",
        "生命周期",
        "资源泄漏",
        "内存泄漏",
        "释放路径",
        "清理路径",
    ],
    "bounds_and_integer": [
        "buffer overflow",
        "overflow",
        "underflow",
        "out of bounds",
        "out-of-bounds",
        "oob",
        "integer overflow",
        "integer truncation",
        "越界",
        "溢出",
        "整数",
        "截断",
    ],
    "null_and_failure": [
        "null pointer",
        "null dereference",
        "unchecked return",
        "failure path",
        "error handling",
        "空指针",
        "失败分支",
        "错误处理",
        "返回值未检查",
    ],
    "temporal_memory": [
        "use after free",
        "use-after-free",
        "uaf",
        "double free",
        "invalid free",
        "释放后使用",
        "重复释放",
        "二次释放",
        "野指针",
    ],
    "concurrency_lock_order": [
        "deadlock",
        "lock order",
        "missing unlock",
        "mutex",
        "死锁",
        "锁顺序",
        "未解锁",
    ],
    "shared_state_race": [
        "data race",
        "race condition",
        "shared state",
        "toctou",
        "竞态",
        "数据竞争",
        "共享状态",
    ],
    "stack_escape": [
        "stack escape",
        "stack address",
        "return stack",
        "async lifetime",
        "栈逃逸",
        "栈地址",
        "局部变量地址",
    ],
    "ownership_contract": [
        "ownership",
        "ownership contract",
        "api contract",
        "caller owns",
        "callee owns",
        "所有权",
        "归属",
        "契约",
    ],
    "string_and_format": [
        "format string",
        "printf",
        "string termination",
        "null termination",
        "格式化字符串",
        "格式串",
        "字符串终止",
    ],
}


SEMANTIC_CONFIDENCE_THRESHOLD = 0.68


def select_vulnerability_skills(
    task: Optional[str],
    available_skill_names: Sequence[str],
    semantic_router: Optional[SemanticSkillRouter] = None,
) -> SkillSelection:
    """Resolve vulnerability skills requested by a task.

    The selector is intentionally conservative: local rules provide stable
    fast-path hints, an optional semantic router can refine intent, and
    uncertain or conflicting results widen back to all available skills.
    """

    available = list(dict.fromkeys(available_skill_names))
    if not task or not task.strip():
        return SkillSelection(
            skills=available,
            restricted=False,
            source="default_all",
            confidence=1.0,
            reasons=["empty task uses every available skill"],
        )

    text = task.lower()
    local_selection = _select_by_local_hints(text, available)
    if (
        semantic_router is None
        or local_selection.confidence >= 0.85
        or (local_selection.restricted and local_selection.confidence >= 0.85)
    ):
        return local_selection
    semantic_selection = _select_by_semantic_router(task, available, semantic_router)
    return _merge_selections(local_selection, semantic_selection, available)


def _select_by_local_hints(text: str, available: Sequence[str]) -> SkillSelection:
    selected: Set[str] = set()
    reasons: List[str] = []

    if _has_general_scope_marker(text) and not _has_explicit_scope_marker(text):
        return SkillSelection(
            skills=list(available),
            restricted=False,
            source="local_all",
            confidence=0.88,
            reasons=["general scope marker keeps all skills active"],
        )

    for group_keyword, group_skills in GROUP_KEYWORDS.items():
        if _contains_non_negated(text, group_keyword.lower()):
            selected.update(group_skills)
            reasons.append(f"group:{group_keyword}")

    for skill, keywords in STRONG_SKILL_KEYWORDS.items():
        if any(_contains_non_negated(text, keyword.lower()) for keyword in keywords):
            selected.add(skill)
            reasons.append(f"strong:{skill}")

    explicit_scope = _has_explicit_scope_marker(text)
    if explicit_scope:
        for skill, keywords in SKILL_KEYWORDS.items():
            if any(_contains_non_negated(text, keyword.lower()) for keyword in keywords):
                selected.add(skill)
                reasons.append(f"scoped_keyword:{skill}")

    filtered = [name for name in available if name in selected]
    if not filtered:
        return SkillSelection(
            skills=list(available),
            restricted=False,
            source="local_all",
            confidence=0.45,
            reasons=["no clear local skill intent"],
        )

    confidence = (
        0.82 if any(reason.startswith(("group:", "strong:")) for reason in reasons) else 0.66
    )
    return SkillSelection(
        skills=filtered,
        restricted=True,
        source="local",
        confidence=confidence,
        reasons=list(dict.fromkeys(reasons)),
    )


def _select_by_semantic_router(
    task: str,
    available: Sequence[str],
    semantic_router: Optional[SemanticSkillRouter],
) -> Optional[SkillSelection]:
    if semantic_router is None:
        return None
    try:
        decision = semantic_router(task, available)
    except Exception:
        return None

    if not isinstance(decision, Mapping):
        return None

    selected = [
        name for name in available if name in {str(item) for item in decision.get("skills", [])}
    ]
    confidence = _coerce_confidence(decision.get("confidence"), default=0.0)
    restricted = bool(decision.get("restricted")) and bool(selected)
    reasons = decision.get("reasons")
    if not isinstance(reasons, list):
        reasons = []

    if not restricted:
        return SkillSelection(
            skills=list(available),
            restricted=False,
            source="semantic",
            confidence=confidence,
            reasons=[str(item) for item in reasons] or ["semantic router did not restrict scope"],
        )

    return SkillSelection(
        skills=selected,
        restricted=True,
        source="semantic",
        confidence=confidence,
        reasons=[str(item) for item in reasons],
    )


def _merge_selections(
    local: SkillSelection,
    semantic: Optional[SkillSelection],
    available: Sequence[str],
) -> SkillSelection:
    if semantic is None:
        return local

    if semantic.confidence < SEMANTIC_CONFIDENCE_THRESHOLD:
        if local.restricted and local.confidence >= 0.80:
            return SkillSelection(
                skills=local.skills,
                restricted=True,
                source="local_semantic_low_confidence",
                confidence=local.confidence,
                reasons=local.reasons + ["semantic router confidence below threshold"],
            )
        return SkillSelection(
            skills=list(available),
            restricted=False,
            source="conservative_all",
            confidence=max(local.confidence, semantic.confidence),
            reasons=local.reasons + semantic.reasons + ["low confidence widened to all skills"],
        )

    if not semantic.restricted:
        if local.restricted and local.confidence >= 0.85:
            return SkillSelection(
                skills=local.skills,
                restricted=True,
                source="local_over_semantic_all",
                confidence=local.confidence,
                reasons=local.reasons + semantic.reasons,
            )
        return semantic

    if not local.restricted:
        return semantic

    combined = [name for name in available if name in set(local.skills) | set(semantic.skills)]
    source = "semantic" if set(local.skills) == set(semantic.skills) else "hybrid"
    return SkillSelection(
        skills=combined,
        restricted=bool(combined),
        source=source,
        confidence=max(local.confidence, semantic.confidence),
        reasons=list(dict.fromkeys(local.reasons + semantic.reasons)),
    )


def filter_report_issues_for_skills(
    report: Dict[str, Any], active_skills: Iterable[str]
) -> Dict[str, Any]:
    """Drop findings that do not match the task-selected skill families."""

    selected = set(active_skills)
    if not selected:
        return report

    issues = report.get("issues")
    if not isinstance(issues, list):
        return report

    filtered = [issue for issue in issues if _issue_matches_skills(issue, selected)]
    if len(filtered) == len(issues):
        return report

    new_report = dict(report)
    new_report["issues"] = filtered
    return new_report


def _has_explicit_scope_marker(text: str) -> bool:
    return any(_contains_scope_marker(text, marker) for marker in EXPLICIT_SCOPE_MARKERS)


def _has_general_scope_marker(text: str) -> bool:
    return any(_contains_scope_marker(text, marker) for marker in GENERAL_SCOPE_MARKERS)


def _contains_scope_marker(text: str, marker: str) -> bool:
    marker = marker.strip().lower()
    if not marker:
        return False
    if marker.isascii() and re.fullmatch(r"[a-z0-9_ ]+", marker):
        return bool(re.search(rf"\b{re.escape(marker)}\b", text))
    return marker in text


def _coerce_confidence(value: Any, *, default: float) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, confidence))


def _contains_non_negated(text: str, needle: str) -> bool:
    start = 0
    while True:
        idx = text.find(needle, start)
        if idx < 0:
            return False
        window = text[max(0, idx - 12) : idx]
        if not any(marker in window for marker in NEGATION_MARKERS):
            return True
        start = idx + len(needle)


def _issue_matches_skills(issue: Any, selected_skills: Set[str]) -> bool:
    if not isinstance(issue, dict):
        return False

    searchable = " ".join(
        str(issue.get(field, ""))
        for field in (
            "category",
            "subcategory",
            "description",
            "reasoning",
            "root_cause",
            "suggested_fix",
            "code_snippet",
        )
    ).lower()

    for skill in selected_skills:
        if any(keyword in searchable for keyword in ISSUE_KEYWORDS.get(skill, [])):
            return True
    return False
