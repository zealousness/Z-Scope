from semantic_fixtures import configured_test_semantics

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.cpp_domains.models import FunctionView, GraphLine
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.java_rules import JavaRuleCandidateGenerator
from zscope.core.candidates.regex import LocalPatternSemantics, RegexCandidateGenerator
from zscope.semantics.contracts import ApiContract


def _clang_rules(code: str, *, semantics=None) -> set[str]:
    configured = configured_test_semantics()
    if semantics is not None:
        configured.merge(semantics)
    issues = ClangAstCfgCandidateGenerator(configured).generate_issues("demo", code, "src/demo.c")
    return {str(issue["rule"]) for issue in issues}


def _java_rules(code: str) -> set[str]:
    issues = JavaRuleCandidateGenerator().generate_issues(
        "example.Controller.handle:void()", code, "src/Controller.java"
    )
    return {str(issue["rule"]) for issue in issues}


def test_overflow_guard_must_bind_operands_and_terminate_the_bad_path() -> None:
    unrelated_and_log_only = """
10 | void *demo(size_t rows, size_t width, size_t other) {
11 |   if (other > SIZE_MAX / width) return NULL;
12 |   if (rows > SIZE_MAX / width) log_error();
13 |   void *result = malloc(rows * width);
14 |   return result;
15 | }
"""
    terminating = """
20 | void *demo(size_t rows, size_t width) {
21 |   if (rows > SIZE_MAX / width) return NULL;
22 |   void *result = malloc(rows * width);
23 |   return result;
24 | }
"""

    assert "clang_cfg_allocation_size_arithmetic_without_overflow_guard" in _clang_rules(
        unrelated_and_log_only
    )
    assert "clang_cfg_allocation_size_arithmetic_without_overflow_guard" not in _clang_rules(
        terminating
    )
    constant_rewrite = """
30 | void *demo(size_t bytes) {
31 |   if (bytes > SIZE_MAX - 8) return NULL;
32 |   void *result = malloc(bytes + 8);
33 |   return result;
34 | }
"""
    assert "clang_cfg_allocation_size_arithmetic_without_overflow_guard" not in _clang_rules(
        constant_rewrite
    )


def test_standard_calloc_is_not_reported_as_unchecked_product() -> None:
    code = """
10 | void *demo(size_t records, size_t bytes) {
11 |   return calloc(records, bytes);
12 | }
"""
    rules = {
        str(issue["rule"])
        for issue in RegexCandidateGenerator().generate_issues("demo", code.strip(), "src/demo.c")
    }
    assert "calloc_product_overflow" not in rules

    semantics = configured_test_semantics()
    semantics.add_api("calloc", "array_reserve", "user_config")
    custom = """
20 | void *demo(size_t records, size_t bytes) {
21 |   return array_reserve(records, bytes);
22 | }
"""
    generator = RegexCandidateGenerator(semantics)
    assert "array_reserve" in generator._calloc_names
    custom_rules = {
        str(issue["rule"])
        for issue in generator.generate_issues("demo", custom.strip(), "src/demo.c")
    }
    assert "calloc_product_overflow" in custom_rules


def test_strchr_log_only_check_does_not_suppress_but_terminating_check_does() -> None:
    log_only = """
10 | int demo(char *text) {
11 |   char *separator = strchr(text, ':');
12 |   if (separator == NULL) log_error();
13 |   return separator[1];
14 | }
"""
    terminating = """
20 | int demo(char *text) {
21 |   char *separator = strchr(text, ':');
22 |   if (separator == NULL) return -1;
23 |   return separator[1];
24 | }
"""

    assert "clang_cfg_unchecked_strchr_result" in _clang_rules(log_only)
    assert "clang_cfg_unchecked_strchr_result" not in _clang_rules(terminating)


def test_java_comments_and_unrelated_security_words_do_not_suppress_candidates() -> None:
    code = """
1 | public void handle(String id, String xml, Principal principal) throws Exception {
2 |   // Runtime.getRuntime().exec(id); authorize owner tenant
3 |   DocumentBuilderFactory parserFactory = DocumentBuilderFactory.newInstance();
4 |   parserFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
5 |   DocumentBuilderFactory otherFactory = DocumentBuilderFactory.newInstance();
6 |   otherFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
7 |   parserFactory.newDocumentBuilder().parse(xml);
8 |   repository.findOrderById(id);
9 | }
"""
    rules = _java_rules(code)

    assert "java_command_execution" not in rules
    assert "java_xxe_factory" in rules
    assert "java_missing_object_authorization" in rules


def test_java_exact_receiver_and_object_bound_guard_are_safe_rewrites() -> None:
    code = """
1 | public void handle(String orderKey, String xml, Principal actor) throws Exception {
2 |   DocumentBuilderFactory parserFactory = DocumentBuilderFactory.newInstance();
3 |   parserFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
4 |   parserFactory.newDocumentBuilder().parse(xml);
5 |   if (!authorize(orderKey, actor)) throw new AccessDeniedException();
6 |   repository.findOrderById(orderKey);
7 | }
"""
    rules = _java_rules(code)

    assert "java_xxe_factory" not in rules
    assert "java_missing_object_authorization" not in rules


def test_java_sql_variable_and_zip_entry_rules_are_name_independent() -> None:
    vulnerable = """
1 | public void query(String name) throws Exception {
2 |   String statementText = "SELECT * FROM users WHERE name='" + name + "'";
3 |   PreparedStatement prepared = connection.prepareStatement(statementText);
4 | }
"""
    unrelated_get_name = """
1 | public String display(User user) {
2 |   return user.getName();
3 | }
"""

    rules = _java_rules(vulnerable)
    assert "java_jdbc_concatenated_sql" in rules
    assert "java_jdbc_fake_prepared_statement" in rules
    assert "java_zip_entry_path_traversal" not in _java_rules(unrelated_get_name)


def test_registry_unlink_rule_uses_object_and_lock_relations_not_names() -> None:
    vulnerable = """
10 | void demo(Record *entry) {
11 |   LOCK(&catalog.guard);
12 |   catalog.anchor = entry->sibling;
13 |   UNLOCK(&catalog.guard);
14 |   free(entry);
15 | }
"""
    protected_release = """
20 | void demo(Record *entry) {
21 |   LOCK(&catalog.guard);
22 |   catalog.anchor = entry->sibling;
23 |   UNLOCK(&catalog.guard);
24 |   LOCK(&catalog.guard);
25 |   free(entry);
26 |   UNLOCK(&catalog.guard);
27 | }
"""

    assert "clang_cfg_registry_unlink_free_after_unlock" in _clang_rules(vulnerable)
    assert "clang_cfg_registry_unlink_free_after_unlock" not in _clang_rules(protected_release)


def test_refcount_race_accepts_renamed_helper_counter_and_prefix_update() -> None:
    vulnerable = """
10 | int demo(const char *key) {
11 |   LOCK(&cache.guard);
12 |   Entry *item = resolve_entry(key);
13 |   UNLOCK(&cache.guard);
14 |   ++item->leases;
15 |   return 0;
16 | }
"""
    protected = """
20 | int demo(const char *key) {
21 |   LOCK(&cache.guard);
22 |   Entry *item = resolve_entry(key);
23 |   ++item->leases;
24 |   UNLOCK(&cache.guard);
25 |   return 0;
26 | }
"""

    assert "clang_cfg_refcount_update_after_unlock" in _clang_rules(vulnerable)
    assert "clang_cfg_refcount_update_after_unlock" not in _clang_rules(protected)


def test_refcount_free_uses_configured_field_and_does_not_accept_two_to_one() -> None:
    semantics = LocalPatternSemantics()
    contract = ApiContract.from_row(
        {
            "symbol_name": "retain_entry",
            "kind": "standard_operation",
            "contract": {
                "carrier": {"kind": "argument", "argument_index": 0},
                "protocol": {
                    "family": "non_atomic_refcount",
                    "operation": "retain",
                    "count_path": "->leases",
                },
            },
        }
    )
    assert contract is not None
    semantics.contracts.add(contract)
    code = """
10 | void demo(Entry *item) {
11 |   item->leases = 2;
12 |   item->leases--;
13 |   free(item);
14 | }
"""

    assert "clang_cfg_shared_resource_freed_without_refcount_protocol" in _clang_rules(
        code, semantics=semantics
    )
    safe = """
20 | void demo(Entry *item) {
21 |   if (--item->leases != 0) return;
22 |   free(item);
23 | }
"""
    assert "clang_cfg_shared_resource_freed_without_refcount_protocol" not in _clang_rules(
        safe, semantics=semantics
    )


def test_owned_member_rule_uses_acquisition_semantics_not_member_spelling() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("allocator", "reserve_leaf", "user_config")
    positive = """
10 | void demo(Container *box) {
11 |   box->orchid = reserve_leaf();
12 |   free(box);
13 | }
"""
    scalar = """
20 | void demo(Container *box) {
21 |   box->payload = 42;
22 |   free(box);
23 | }
"""

    assert "clang_cfg_parent_release_without_owned_member_cleanup" in _clang_rules(
        positive, semantics=semantics
    )
    assert "clang_cfg_parent_release_without_owned_member_cleanup" not in _clang_rules(
        scalar, semantics=semantics
    )


def test_graph_callback_self_destroy_is_invariant_to_all_identifier_names() -> None:
    destroy = FunctionView(
        "finish_event",
        "src/demo.c",
        "void finish_event(void *cookie)",
        (
            GraphLine(1, "Event *target = (Event *)cookie;", "Event *target = (Event *)cookie;", 0),
            GraphLine(2, "free(target);", "free(target);", 1),
        ),
        (),
    )
    dispatch = FunctionView(
        "dispatch_event",
        "src/demo.c",
        "void dispatch_event(Event *current)",
        tuple(
            GraphLine(index + 10, text, text, index)
            for index, text in enumerate(
                (
                    "current->opaque = current;",
                    "current->handler = finish_event;",
                    "current->handler(current->opaque);",
                    "current->state = DONE;",
                )
            )
        ),
        ("finish_event",),
    )
    generator = GraphCandidateGenerator(object(), configured_test_semantics())
    issues: list[dict] = []

    generator._rule_callback_self_destroy_protocols((destroy, dispatch), issues)

    assert "callback_can_free_current_event_before_reacquire" in {issue["rule"] for issue in issues}
