"""Select vulnerability-mining skills from a user task."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


@dataclass
class SkillSelection:
    """Resolved skill subset for one vulnerability analyzer invocation."""

    skills: List[str]
    restricted: bool


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


def select_vulnerability_skills(
    task: Optional[str],
    available_skill_names: Sequence[str],
) -> SkillSelection:
    """Resolve the vulnerability skills explicitly requested by a task.

    Empty or unrecognized tasks keep the historical behavior and use every
    available skill. Any recognized concern restricts the run to that subset.
    """

    available = list(dict.fromkeys(available_skill_names))
    if not task or not task.strip():
        return SkillSelection(skills=available, restricted=False)

    text = task.lower()
    selected: Set[str] = set()

    for group_keyword, group_skills in GROUP_KEYWORDS.items():
        if _contains_non_negated(text, group_keyword.lower()):
            selected.update(group_skills)

    for skill, keywords in SKILL_KEYWORDS.items():
        if any(_contains_non_negated(text, keyword.lower()) for keyword in keywords):
            selected.add(skill)

    filtered = [name for name in available if name in selected]
    if not filtered:
        return SkillSelection(skills=available, restricted=False)
    return SkillSelection(skills=filtered, restricted=True)


def filter_report_issues_for_skills(report: Dict[str, Any], active_skills: Iterable[str]) -> Dict[str, Any]:
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
