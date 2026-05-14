from zscope.orchestration.skill_selection import select_vulnerability_skills

AVAILABLE = [
    "resource_lifecycle",
    "bounds_and_integer",
    "null_and_failure",
    "temporal_memory",
]


def test_semantic_router_handles_non_keyword_intent() -> None:
    def router(task: str, available: list[str]):
        assert "异常路径" in task
        return {
            "skills": ["null_and_failure"],
            "restricted": True,
            "confidence": 0.84,
            "reasons": ["failure-path intent"],
        }

    selection = select_vulnerability_skills(
        "检查异常路径安全性",
        AVAILABLE,
        semantic_router=router,
    )

    assert selection.restricted is True
    assert selection.skills == ["null_and_failure"]
    assert selection.source == "semantic"


def test_low_confidence_semantic_router_widens_to_all() -> None:
    def router(task: str, available: list[str]):
        return {
            "skills": ["bounds_and_integer"],
            "restricted": True,
            "confidence": 0.31,
            "reasons": ["weak guess"],
        }

    selection = select_vulnerability_skills(
        "看看这个函数有没有安全问题",
        AVAILABLE,
        semantic_router=router,
    )

    assert selection.restricted is False
    assert selection.skills == AVAILABLE
    assert selection.source == "conservative_all"


def test_general_scope_keeps_all_skills() -> None:
    selection = select_vulnerability_skills(
        "general security audit",
        AVAILABLE,
    )

    assert selection.restricted is False
    assert selection.skills == AVAILABLE


def test_local_and_semantic_results_are_widened_by_union() -> None:
    def router(task: str, available: list[str]):
        return {
            "skills": ["bounds_and_integer"],
            "restricted": True,
            "confidence": 0.87,
            "reasons": ["overflow intent"],
        }

    selection = select_vulnerability_skills(
        "focus on cleanup and overflow paths",
        AVAILABLE,
        semantic_router=router,
    )

    assert selection.restricted is True
    assert selection.skills == ["resource_lifecycle", "bounds_and_integer"]
    assert selection.source == "hybrid"
