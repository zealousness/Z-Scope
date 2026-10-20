"""Actual project-state SQLite, synthetic plan: unreadable dependencies miss."""

from types import SimpleNamespace
import sqlite3

from zscope.config.user_config_store import UserConfigStore
from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint
from zscope.orchestration.instance_semantics_context import SEMANTICS_POLICY
from zscope.retrieval.instance_index import instance_scope_from_entry_instance


def fingerprint(plan, config):
    # Synthetic plan metadata only: no semantic effects or persisted reuse are
    # authorized by this dependency-digest test. The mandatory production map
    # is explicit and matches every planned exact scope; no empty-map fallback.
    semantics = {}
    for instance in plan.instances:
        scope = instance_scope_from_entry_instance(instance)
        semantics[scope.identity] = SimpleNamespace(
            scope=scope,
            authority_policy=SEMANTICS_POLICY,
            schema="zscope.instance-semantics.v1",
            digest="synthetic-dependency-probe",
        )
    return compute_plan_fingerprint(plan, config, semantics_by_instance=semantics)


def setup(tmp_path, state_name="state", validate=True):
    store = UserConfigStore(tmp_path / state_name)
    config = SimpleNamespace(
        analysis=SimpleNamespace(user_config_db=str(tmp_path / state_name)),
        project=SimpleNamespace(
            user_config_file=None, project_root=tmp_path, source_root=tmp_path, language="c_cpp"
        ),
        rules=SimpleNamespace(enabled_ids=[], disabled_ids=[]),
    )
    plan = SimpleNamespace(
        instances=[
            SimpleNamespace(
                identity="synthetic-instance",
                build_context_id="synthetic-build",
                usr="synthetic-usr",
                source="unit.c",
                function_names=("f",),
            )
        ]
    )
    if validate:
        assert fingerprint(plan, config) is not None
    return store, plan, config


def test_corrupt_answer_database_does_not_equal_verified_empty_answers(tmp_path):
    store, plan, config = setup(tmp_path)
    store.db_path.write_bytes(b"this is not a SQLite database\n")
    assert fingerprint(plan, config) is None


def test_unreadable_answer_schema_does_not_equal_verified_empty_answers(tmp_path):
    store, plan, config = setup(tmp_path)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("ALTER TABLE protocol_assumption_answers DROP COLUMN origin")
    assert fingerprint(plan, config) is None


def test_answer_digest_readonly_uri_preserves_a_hash_character_in_the_path(tmp_path):
    _, plan, config = setup(tmp_path, state_name="state#fragment", validate=False)
    wrong_path = tmp_path / "state"
    assert not wrong_path.exists()
    assert fingerprint(plan, config) is not None
    assert (
        not wrong_path.exists()
    ), "a readonly digest lookup must not create a different database via URI fragment parsing"
