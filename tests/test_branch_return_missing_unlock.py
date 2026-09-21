"""Branch-return missing-unlock detection (REAL-023 shape, 20260908 trial)."""

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from tests.test_clang_ast_cfg_candidates import _rules

REAL023_SHAPE = """
10 | int _runtime_link_allocated_node(const char *key) {
11 |     LOCK(&g_service_aux_lock);
12 |     ServiceNode *node = _service_alloc_node(key, "unlock");
13 |     if (!node) {
14 |         return -1;
15 |     }
16 |     UNLOCK(&g_service_aux_lock);
17 |     SAFE_FREE(node->payload);
18 |     SAFE_FREE(node->name);
19 |     SAFE_FREE(node);
20 |     return 0;
21 | }
"""

PROPER_BRANCH_UNLOCK = """
10 | int demo(int fail) {
11 |     LOCK(&g_service_aux_lock);
12 |     if (fail) {
13 |         UNLOCK(&g_service_aux_lock);
14 |         return -1;
15 |     }
16 |     UNLOCK(&g_service_aux_lock);
17 |     return 0;
18 | }
"""

NEVER_RELEASED = """
10 | int demo(int fail) {
11 |     LOCK(&g_service_aux_lock);
12 |     if (fail) {
13 |         return -1;
14 |     }
15 |     return 0;
16 | }
"""


def test_branch_early_return_missing_unlock_is_detected():
    issues = _rules(REAL023_SHAPE)
    hit = [i for i in issues if i["rule"] == "clang_cfg_return_with_lock_held"]
    assert hit, "早退分支漏解锁必须被检出"
    assert hit[0]["defect_class"] == "missing_unlock"
    assert "line 11" in "\n".join(hit[0].get("positive_evidence", []))
    assert "line 14" in "\n".join(hit[0].get("positive_evidence", []))


def test_proper_branch_unlock_is_not_flagged():
    rules = {i["rule"] for i in _rules(PROPER_BRANCH_UNLOCK)}
    assert "clang_cfg_return_with_lock_held" not in rules


def test_never_released_lock_emits_once_via_main_path():
    issues = [i for i in _rules(NEVER_RELEASED)
              if i["rule"] == "clang_cfg_return_with_lock_held"]
    assert len(issues) == 1  # 主路径 return 触发一次，分支不重复
